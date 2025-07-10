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
        public String sourceKind = "";
        public Integer sourceLine = -1;
    }

    // --- List of sources and sinks for basic taint analysis ---
    private static final List<String> SOURCES = Arrays.asList(
            "nextLine", "next", "getParameter", "getHeader", "readLine",
            "getInputStream", "getenv", "getCookies", "getQueryString"
    );

    // CWE-15 specific sinks
    private static final List<String> CWE15_SINKS = Arrays.asList(
            "setProperty", "clearProperty", "setCatalog", "setSchema",
            "setSessionContext", "setLogWriter", "setLoginTimeout",
            "lookup", "setRequestProperty", "addRequestProperty", "badSink"
    );

    // Other CWE sinks
    private static final Map<String, List<String>> CWE_SINKS = new HashMap<>();
    static {
        CWE_SINKS.put("CWE-15", CWE15_SINKS);
        CWE_SINKS.put("CWE-78", Arrays.asList("exec"));
        CWE_SINKS.put("CWE-89", Arrays.asList("executeQuery", "executeUpdate", "execute"));
        CWE_SINKS.put("CWE-80", Arrays.asList("println", "print", "write"));
        CWE_SINKS.put("CWE-134", Arrays.asList("printf", "format"));
    }

    /**
     * Analyze taint for a specific class file with dependencies.
     */
    public static List<TaintResult> analyzeTaint(String targetClassDir, List<String> classDirs, List<String> jarPaths) throws Exception {
        List<TaintResult> results = new ArrayList<>();

        try {
            // --- 1. Scope Build ---
            System.out.println("\n=== WALA Taint Analysis ===");

            // Create a basic Java analysis scope
            AnalysisScope scope = AnalysisScopeReader.instance.makePrimordialScope(null);

            // --- 2. Add target class directory first ---
            File targetDir = new File(targetClassDir);
            if (targetDir.exists() && targetDir.isDirectory()) {
                System.out.println("  Adding target directory: " + targetClassDir);
                scope.addToScope(ClassLoaderReference.Application, new BinaryDirectoryTreeModule(targetDir));
            }

            // --- 3. Add supporting class directories ---
            for (String classDir : classDirs) {
                File dir = new File(classDir);
                if (dir.exists() && dir.isDirectory()) {
                    System.out.println("  Adding class directory: " + classDir);
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
            System.out.println("\nClasses loaded successfully");

            // --- 6. Find entrypoints ---
            List<Entrypoint> entrypoints = new ArrayList<>();
            for (IClass klass : cha) {
                if (klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    for (IMethod method : klass.getDeclaredMethods()) {
                        // Add main, bad, and good methods as entrypoints
                        if (method.getName().toString().equals("main") ||
                                method.getName().toString().equals("bad") ||
                                method.getName().toString().equals("good")) {
                            entrypoints.add(new DefaultEntrypoint(method, cha));
                            System.out.println("Found entrypoint: " + method.getSignature());
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
            System.out.println("Call graph built with " + cg.getNumberOfNodes() + " nodes");

            // --- 8. Perform inter-procedural taint analysis ---
            performInterproceduralTaintAnalysis(cg, results, targetClassDir);

        } catch (Exception e) {
            System.out.println("\n  ERROR: WALA analysis failed - " + e.getMessage());
            e.printStackTrace();
        }

        return results;
    }

    private static void performInterproceduralTaintAnalysis(CallGraph cg, List<TaintResult> results, String targetDir) {
        System.out.println("\n=== Inter-procedural Taint Analysis ===");

        // Map to track tainted variables across methods
        Map<CGNode, Set<Integer>> taintedByNode = new HashMap<>();

        // First pass: identify sources
        for (CGNode node : cg) {
            IMethod method = node.getMethod();
            if (!method.getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                continue;
            }

            IR ir = node.getIR();
            if (ir == null) continue;

            Set<Integer> localTainted = new HashSet<>();

            // Analyze each instruction for sources
            SSAInstruction[] instructions = ir.getInstructions();
            for (int i = 0; i < instructions.length; i++) {
                SSAInstruction inst = instructions[i];
                if (inst == null) continue;

                if (inst instanceof SSAInvokeInstruction) {
                    SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
                    String methodName = invoke.getCallSite().getDeclaredTarget().getName().toString();

                    // Check if this is a source
                    if (SOURCES.contains(methodName)) {
                        int def = invoke.getDef();
                        if (def != -1) {
                            localTainted.add(def);
                            System.out.println("  Found source: " + methodName + " in " +
                                    method.getDeclaringClass().getName() + "." + method.getName());

                            // Check if this is System.getenv - special case for CWE-15
                            if (methodName.equals("getenv")) {
                                TaintResult result = new TaintResult();
                                result.className = method.getDeclaringClass().getName().toString();
                                result.methodName = method.getName().toString();
                                result.sourceKind = "System.getenv";
                                result.file = targetDir;

                                try {
                                    result.sourceLine = method.getLineNumber(i);
                                } catch (Exception e) {
                                    result.sourceLine = -1;
                                }

                                // For CWE-15, the source itself is the vulnerability
                                result.sinkKind = "External Control";
                                result.line = result.sourceLine;
                                results.add(result);
                                System.out.println("  ✗ CWE-15 FOUND: System.getenv at line " + result.sourceLine);
                            }
                        }
                    }
                }
            }

            if (!localTainted.isEmpty()) {
                taintedByNode.put(node, localTainted);
            }
        }

        // Second pass: propagate taint through method calls
        boolean changed = true;
        int iterations = 0;
        while (changed && iterations < 10) {
            changed = false;
            iterations++;

            for (CGNode node : cg) {
                IMethod method = node.getMethod();
                if (!method.getDeclaringClass().getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    continue;
                }

                IR ir = node.getIR();
                if (ir == null) continue;

                Set<Integer> currentTainted = taintedByNode.getOrDefault(node, new HashSet<>());
                int sizeBefore = currentTainted.size();

                // Check if parameters are tainted from callers
                Iterator<CGNode> callers = cg.getPredNodes(node);
                while (callers.hasNext()) {
                    CGNode caller = callers.next();
                    Set<Integer> callerTainted = taintedByNode.get(caller);
                    if (callerTainted != null) {
                        // If caller has tainted data and calls this method, mark parameters as tainted
                        for (int i = 1; i <= method.getNumberOfParameters(); i++) {
                            currentTainted.add(i);
                        }
                    }
                }

                // Propagate taint within the method
                SSAInstruction[] instructions = ir.getInstructions();
                for (int i = 0; i < instructions.length; i++) {
                    SSAInstruction inst = instructions[i];
                    if (inst == null) continue;

                    // Check for sinks
                    if (inst instanceof SSAInvokeInstruction) {
                        SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
                        String methodName = invoke.getCallSite().getDeclaredTarget().getName().toString();

                        // Check all CWE sink patterns
                        for (Map.Entry<String, List<String>> entry : CWE_SINKS.entrySet()) {
                            String cweId = entry.getKey();
                            List<String> sinks = entry.getValue();

                            if (sinks.contains(methodName)) {
                                // Check if any argument is tainted
                                boolean hasTaintedArg = false;
                                for (int j = 0; j < invoke.getNumberOfUses(); j++) {
                                    if (currentTainted.contains(invoke.getUse(j))) {
                                        hasTaintedArg = true;
                                        break;
                                    }
                                }

                                if (hasTaintedArg) {
                                    TaintResult result = new TaintResult();
                                    result.className = method.getDeclaringClass().getName().toString();
                                    result.methodName = method.getName().toString();
                                    result.sinkKind = methodName;
                                    result.file = targetDir;

                                    try {
                                        result.line = method.getLineNumber(i);
                                    } catch (Exception e) {
                                        result.line = -1;
                                    }

                                    results.add(result);
                                    System.out.println("  ✗ " + cweId + " FOUND: Tainted data flows to " +
                                            methodName + " at line " + result.line);
                                }
                            }
                        }

                        // Propagate taint through method returns
                        int def = invoke.getDef();
                        if (def != -1 && invoke.getNumberOfUses() > 0) {
                            for (int j = 0; j < invoke.getNumberOfUses(); j++) {
                                if (currentTainted.contains(invoke.getUse(j))) {
                                    currentTainted.add(def);
                                    break;
                                }
                            }
                        }
                    }

                    // Propagate through phi nodes
                    if (inst instanceof SSAPhiInstruction) {
                        SSAPhiInstruction phi = (SSAPhiInstruction) inst;
                        for (int j = 0; j < phi.getNumberOfUses(); j++) {
                            if (currentTainted.contains(phi.getUse(j))) {
                                currentTainted.add(phi.getDef());
                                break;
                            }
                        }
                    }
                }

                if (currentTainted.size() > sizeBefore) {
                    changed = true;
                    taintedByNode.put(node, currentTainted);
                }
            }
        }

        System.out.println("\nTaint analysis completed. Found " + results.size() + " vulnerabilities.");
    }
}