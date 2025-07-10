package s2e.WalaIntegration;

import com.ibm.wala.classLoader.BinaryDirectoryTreeModule;
import com.ibm.wala.classLoader.IClass;
import com.ibm.wala.classLoader.Language;
import com.ibm.wala.classLoader.*;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.callgraph.impl.DefaultEntrypoint;
import com.ibm.wala.ipa.callgraph.impl.Util;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.ssa.*;
import com.ibm.wala.types.ClassLoaderReference;
import com.ibm.wala.ipa.callgraph.AnalysisCacheImpl;
import com.ibm.wala.ipa.callgraph.AnalysisOptions;

import java.io.File;
import java.util.*;
import java.util.jar.JarFile;

public class SimplifiedTaintAnalyzer {

    private final String targetClassName;
    private final Map<String, List<String>> cweSources;
    private final Map<String, List<String>> cweSinks;

    // Collect details
    private final Map<String, List<TaintElement>> foundSourcesPerCWE = new HashMap<>();
    private final Map<String, List<TaintElement>> foundSinksPerCWE = new HashMap<>();

    public static class TaintElement {
        String cweId;
        public String methodName;
        public String className;
        public String containingMethod;
        public String containingClassName;
        public String sourceFileName;  // May be null if no debug info
        public int line;

        public TaintElement(String cweId, String methodName, String className, String containingMethod, String containingClassName, String sourceFileName, int line) {
            this.cweId = cweId;
            this.methodName = methodName;
            this.className = className;
            this.containingMethod = containingMethod;
            this.containingClassName = containingClassName;
            this.sourceFileName = sourceFileName;
            this.line = line;
        }

        @Override
        public String toString() {
            return methodName + " in " + containingMethod + " (" + className +
                    (sourceFileName != null ? ", file: " + sourceFileName : "") +
                    ") at line " + (line > 0 ? line : "unknown");
        }
    }

    public SimplifiedTaintAnalyzer(String targetClassName,
                                   Map<String, List<String>> sources,
                                   Map<String, List<String>> sinks) {
        this.targetClassName = targetClassName;
        this.cweSources = sources;
        this.cweSinks = sinks;
    }

    /**
     * Checks if there's a possible taint path in the call graph.
     * Returns true if any CWE has both sources and sinks.
     */
    public boolean hasTaintPath(String targetDir, List<String> classDirs, List<String> jarPaths) throws Exception {
        try {
            // Build analysis scope
            AnalysisScope scope = AnalysisScopeReader.instance.makePrimordialScope(null);

            // Add directories and JARs
            File targetDirFile = new File(targetDir);
            if (targetDirFile.exists() && targetDirFile.isDirectory()) {
                scope.addToScope(ClassLoaderReference.Application, new BinaryDirectoryTreeModule(targetDirFile));
            }

            for (String classDir : classDirs) {
                File dir = new File(classDir);
                if (dir.exists() && dir.isDirectory()) {
                    scope.addToScope(ClassLoaderReference.Application, new BinaryDirectoryTreeModule(dir));
                }
            }

            for (String jarPath : jarPaths) {
                File jarFile = new File(jarPath);
                if (jarFile.exists() && jarFile.isFile()) {
                    scope.addToScope(ClassLoaderReference.Application, new JarFileModule(new JarFile(jarFile)));
                }
            }

            // Build class hierarchy
            ClassHierarchy cha = ClassHierarchyFactory.make(scope);

            // Find ALL methods in our target class as entrypoints
            List<Entrypoint> entrypoints = new ArrayList<>();
            for (IClass klass : cha) {
                if (!klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    continue;
                }

                String className = klass.getName().toString();
                // Only analyze the target class
                if (className.contains(targetClassName)) {
                    // Add ALL declared methods as entrypoints (except constructors)
                    for (IMethod method : klass.getDeclaredMethods()) {
                        if (!method.isInit() && !method.isClinit()) {
                            entrypoints.add(new DefaultEntrypoint(method, cha));
                            System.out.println("  Adding entrypoint: " + method.getName());
                        }
                    }
                }
            }

            if (entrypoints.isEmpty()) {
                System.out.println("  No methods found in target class");
                return false;
            }

            // Build call graph
            AnalysisOptions options = new AnalysisOptions(scope, entrypoints);
            options.setReflectionOptions(AnalysisOptions.ReflectionOptions.NONE);
            IAnalysisCacheView cache = new AnalysisCacheImpl();

            CallGraphBuilder<?> builder = Util.makeZeroCFABuilder(
                    Language.JAVA, options, cache, cha
            );

            CallGraph cg = builder.makeCallGraph(options, null);
            System.out.println("  Call graph built with " + cg.getNumberOfNodes() + " nodes");

            // Reset collections
            foundSourcesPerCWE.clear();
            foundSinksPerCWE.clear();

            // Do a traversal
            Set<CGNode> visited = new HashSet<>();
            Queue<CGNode> worklist = new LinkedList<>();
            worklist.addAll(cg.getEntrypointNodes());

            while (!worklist.isEmpty()) {
                CGNode node = worklist.poll();
                if (visited.contains(node)) continue;
                visited.add(node);

                if (isApplicationClass(node)) {
                    checkNodeForSourcesAndSinks(node);
                }

                // Add successors
                Iterator<CGNode> succs = cg.getSuccNodes(node);
                while (succs.hasNext()) {
                    CGNode succ = succs.next();
                    if (!visited.contains(succ)) {
                        worklist.add(succ);
                    }
                }
            }

            // Check if any CWE has both source and sink
            boolean hasAnyPath = false;
            for (String cweId : cweSources.keySet()) {
                if (foundSourcesPerCWE.containsKey(cweId) && !foundSourcesPerCWE.get(cweId).isEmpty() &&
                        foundSinksPerCWE.containsKey(cweId) && !foundSinksPerCWE.get(cweId).isEmpty()) {
                    hasAnyPath = true;
                    System.out.println("  Found sources and sinks for " + cweId);
                }
            }

            return hasAnyPath;

        } catch (Exception e) {
            System.err.println("Simplified taint analysis failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private void checkNodeForSourcesAndSinks(CGNode node) {
        IR ir = node.getIR();
        if (ir == null) return;

        for (SSAInstruction inst : ir.getInstructions()) {
            if (inst == null || !(inst instanceof SSAInvokeInstruction)) continue;

            SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
            String methodName = invoke.getCallSite().getDeclaredTarget().getName().toString();
            String declaringClass = invoke.getCallSite().getDeclaredTarget().getDeclaringClass().getName().toString();
            String containingMethod = node.getMethod().getName().toString();
            String containingClass = node.getMethod().getDeclaringClass().getName().toString();
            int ssaIndex = inst.iIndex();
            int bytecodeIndex = -1;
            if (ssaIndex >= 0) {
                bytecodeIndex = node.getIR().getControlFlowGraph().getProgramCounter(ssaIndex);
            }
            int line = (bytecodeIndex >= 0) ? node.getMethod().getLineNumber(bytecodeIndex) : -1;
            String sourceFile = node.getMethod().getDeclaringClass().getSourceFileName();  // May be null

            // Check sources per CWE
            for (Map.Entry<String, List<String>> entry : cweSources.entrySet()) {
                String cweId = entry.getKey();
                List<String> sources = entry.getValue();
                if (sources.contains(methodName)) {
                    boolean matches = true;
                    if (methodName.equals("getenv") && !declaringClass.equals("Ljava/lang/System")) {
                        matches = false;
                    }
                    if (matches) {
                        foundSourcesPerCWE.computeIfAbsent(cweId, k -> new ArrayList<>())
                                .add(new TaintElement(cweId, methodName, declaringClass, containingMethod, containingClass, sourceFile, line));
                        System.out.println("    Found source for " + cweId + ": " + methodName + " in " + containingMethod + " at line " + line);
                    }
                }
            }

            // Check sinks per CWE
            for (Map.Entry<String, List<String>> entry : cweSinks.entrySet()) {
                String cweId = entry.getKey();
                List<String> sinks = entry.getValue();
                if (sinks.contains(methodName)) {
                    foundSinksPerCWE.computeIfAbsent(cweId, k -> new ArrayList<>())
                            .add(new TaintElement(cweId, methodName, declaringClass, containingMethod, containingClass, sourceFile, line));
                    System.out.println("    Found sink for " + cweId + ": " + methodName + " in " + containingMethod + " at line " + line);
                }
            }
        }
    }

    // Getters for reporting
    public Map<String, List<TaintElement>> getFoundSinksPerCWE() {
        return foundSinksPerCWE;
    }

    public Map<String, List<TaintElement>> getFoundSourcesPerCWE() {
        return foundSourcesPerCWE;
    }

    private boolean isApplicationClass(CGNode node) {
        return node.getMethod().getDeclaringClass().getClassLoader()
                .getReference().equals(ClassLoaderReference.Application);
    }
}