package s2e.WalaAnalyzer;

import com.ibm.wala.classLoader.*;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.ssa.*;

import java.util.*;
import java.io.File;
import java.util.jar.JarFile;

public class WalaAnalyzer {

    public static class TaintResult {
        public String file;
        public String className;
        public String methodName;
        public Set<String> taintedVariables = new HashSet<>();
        public Integer line = -1;
        public String sinkKind = "";
        public String sinkVariable = "";
    }

    // --- List of sources and sinks for basic taint analysis ---
    private static final List<String> SOURCES = Arrays.asList(
            "nextLine", "getParameter", "getHeader", "readLine", "getInputStream", "getenv"
    );
    private static final List<String> SINKS = Arrays.asList(
            "setProperty", "clearProperty"  // System.setProperty, System.clearProperty
    );

    /**
     * Analyze taint for a specific class file with dependencies.
     *
     * @param targetClassDir Directory containing the target .class file to analyze
     * @param classDirs List of directories containing supporting .class files
     * @param jarPaths List of absolute paths to dependency .jar files
     * @return List of TaintResult for user-controlled data leading to dangerous sinks
     */
    public static List<TaintResult> analyzeTaint(String targetClassDir, List<String> classDirs, List<String> jarPaths) throws Exception {
        List<TaintResult> results = new ArrayList<>();

        try {
            // --- 1. Scope Build ---
            System.out.println("=== Building AnalysisScope ===");

            // Create a basic Java analysis scope
            AnalysisScope scope = AnalysisScopeReader.instance.makePrimordialScope(null);

            // --- 2. Add target class directory first ---
            File targetDir = new File(targetClassDir);
            if (targetDir.exists() && targetDir.isDirectory()) {
                System.out.println("  Adding target directory: " + targetClassDir);
                File[] classFiles = targetDir.listFiles((d, name) -> name.endsWith(".class"));
                System.out.println("    Found " + (classFiles != null ? classFiles.length : 0) + " .class files");
                scope.addToScope(ClassLoaderReference.Application, new BinaryDirectoryTreeModule(targetDir));
            }

            // --- 3. Add supporting class directories ---
            for (String classDir : classDirs) {
                File dir = new File(classDir);
                if (dir.exists() && dir.isDirectory()) {
                    System.out.println("  Adding class directory: " + classDir);
                    File[] classFiles = dir.listFiles((d, name) -> name.endsWith(".class"));
                    System.out.println("    Found " + (classFiles != null ? classFiles.length : 0) + " .class files");
                    scope.addToScope(ClassLoaderReference.Application, new BinaryDirectoryTreeModule(dir));
                }
            }

            // --- 4. Add jars ---
            for (String jarPath : jarPaths) {
                File jarFile = new File(jarPath);
                if (jarFile.exists() && jarFile.isFile() && jarPath.endsWith(".jar")) {
                    System.out.println("  Adding JAR: " + jarPath);
                    scope.addToScope(ClassLoaderReference.Application, new JarFile(jarFile));
                }
            }

            // --- 5. ClassHierarchy ---
            ClassHierarchy cha = ClassHierarchyFactory.make(scope);
            System.out.println("\n=== Application Classes in ClassHierarchy ===");
            int appClassCount = 0;
            for (IClass klass : cha) {
                if (klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    System.out.println("  " + klass.getName());
                    appClassCount++;
                    if (appClassCount > 10) {
                        System.out.println("  ... (showing first 10 classes)");
                        break;
                    }
                }
            }
            System.out.println("Total application classes loaded: " + cha.getNumberOfClasses());

            // --- 6. Find entrypoints ---
            List<Entrypoint> entrypoints = new ArrayList<>();
            for (IClass klass : cha) {
                if (klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    for (IMethod method : klass.getDeclaredMethods()) {
                        if (method.getName().toString().equals("main") && method.isStatic()) {
                            entrypoints.add(new DefaultEntrypoint(method, cha));
                            System.out.println("Found main entrypoint: " + method.getSignature());
                        }
                        // Add bad() and good() methods as entrypoints (Juliet test pattern)
                        else if (method.getName().toString().equals("bad") ||
                                method.getName().toString().equals("good")) {
                            entrypoints.add(new DefaultEntrypoint(method, cha));
                            System.out.println("Found Juliet entrypoint: " + method.getSignature());
                        }
                    }
                }
            }

            if (entrypoints.isEmpty()) {
                System.out.println("No standard entrypoints found. Using all public methods...");
                for (IClass klass : cha) {
                    if (klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                        for (IMethod method : klass.getDeclaredMethods()) {
                            if (method.isPublic() && !method.isAbstract()) {
                                entrypoints.add(new DefaultEntrypoint(method, cha));
                            }
                        }
                    }
                }
            }

            // --- 7. Build Call Graph ---
            AnalysisOptions options = new AnalysisOptions(scope, entrypoints);
            options.setReflectionOptions(AnalysisOptions.ReflectionOptions.NONE);
            IAnalysisCacheView cache = new AnalysisCacheImpl();

            CallGraphBuilder<?> builder = com.ibm.wala.ipa.callgraph.impl.Util.makeZeroCFABuilder(
                    Language.JAVA, options, cache, cha
            );

            System.out.println("\nBuilding call graph...");
            CallGraph cg = builder.makeCallGraph(options, null);

            System.out.println("\n=== Call Graph Statistics ===");
            System.out.println("Total nodes in call graph: " + cg.getNumberOfNodes());

            // --- 8. Perform taint analysis ---
            int methodsAnalyzed = 0;
            for (CGNode node : cg) {
                IMethod method = node.getMethod();

                // Skip non-application methods
                if (!method.getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    continue;
                }

                IR ir = node.getIR();
                if (ir == null) continue;

                methodsAnalyzed++;
                System.out.println("\nAnalyzing method " + methodsAnalyzed + ": " + method.getName());

                // Track tainted variables
                Set<Integer> taintedVars = new HashSet<>();

                // Analyze each instruction
                SSAInstruction[] instructions = ir.getInstructions();
                for (int i = 0; i < instructions.length; i++) {
                    SSAInstruction inst = instructions[i];
                    if (inst == null) continue;

                    // Check for source methods (taint introduction)
                    if (inst instanceof SSAInvokeInstruction) {
                        SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
                        String methodName = invoke.getCallSite().getDeclaredTarget().getName().toString();

                        // Check if this is a source
                        if (SOURCES.contains(methodName)) {
                            int def = invoke.getDef();
                            if (def != -1) {
                                taintedVars.add(def);
                                System.out.println("  Found source: " + methodName + " -> v" + def);
                            }
                        }

                        // Check if this is a sink with tainted arguments
                        if (SINKS.contains(methodName)) {
                            boolean hasTaintedArg = false;
                            for (int j = 0; j < invoke.getNumberOfUses(); j++) {
                                if (taintedVars.contains(invoke.getUse(j))) {
                                    hasTaintedArg = true;
                                    break;
                                }
                            }

                            if (hasTaintedArg) {
                                TaintResult result = new TaintResult();
                                result.className = method.getDeclaringClass().getName().toString();
                                result.methodName = method.getName().toString();
                                result.sinkKind = methodName;
                                result.file = targetClassDir;

                                // Try to get line number
                                try {
                                    result.line = method.getLineNumber(i);
                                } catch (Exception e) {
                                    result.line = -1;
                                }

                                results.add(result);
                                System.out.println("  ✗ FOUND VULNERABILITY: Tainted data flows to " + methodName);
                            }
                        }
                    }

                    // Propagate taint through assignments
                    if (inst instanceof SSAPhiInstruction) {
                        SSAPhiInstruction phi = (SSAPhiInstruction) inst;
                        for (int j = 0; j < phi.getNumberOfUses(); j++) {
                            if (taintedVars.contains(phi.getUse(j))) {
                                taintedVars.add(phi.getDef());
                                break;
                            }
                        }
                    }
                }
            }

            System.out.println("\nTotal methods analyzed: " + methodsAnalyzed);

        } catch (com.ibm.wala.ipa.cha.ClassHierarchyException e) {
            System.out.println("\n  ERROR: WALA ClassHierarchy failed - " + e.getMessage());
            System.out.println("  This often happens with Java 11+ due to module system issues.");
            System.out.println("  Falling back to AST-only analysis.");
        } catch (Exception e) {
            System.out.println("\n  ERROR: WALA analysis failed - " + e.getClass().getName() + ": " + e.getMessage());
            e.printStackTrace();
        }

        return results;
    }
}