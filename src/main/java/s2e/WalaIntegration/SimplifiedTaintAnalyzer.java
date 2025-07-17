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
    private final Map<String, List<String>> cweSanitizers;

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
                                   Map<String, List<String>> sinks,
                                   Map<String, List<String>> sanitizers) {
        this.targetClassName = targetClassName;
        this.cweSources = sources;
        this.cweSinks = sinks;
        this.cweSanitizers = sanitizers;
    }

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

            // Debug: Count and list application classes
            int appClassCount = 0;
            List<String> appClasses = new ArrayList<>();
            for (IClass klass : cha) {
                if (klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    appClassCount++;
                    appClasses.add(klass.getName().toString());
                }
            }
            System.out.println("  Application classes loaded: " + appClassCount);
            if (appClassCount < 10) {  // List if few for debug
                System.out.println("  Loaded classes: " + appClasses);
            }

            // Find ALL methods in our target class as entrypoints
            List<Entrypoint> entrypoints = new ArrayList<>();
            for (IClass klass : cha) {
                if (!klass.getClassLoader().getReference().equals(ClassLoaderReference.Application)) {
                    continue;
                }

                String className = klass.getName().toString();
                String normalizedTarget = "L" + targetClassName.replace('.', '/');
                if (className.equals(normalizedTarget)) {
                    for (IMethod method : klass.getDeclaredMethods()) {
                        if (!method.isInit() && !method.isClinit()) {
                            entrypoints.add(new DefaultEntrypoint(method, cha));
                            System.out.println("  Adding entrypoint: " + method.getName());
                        }
                    }
                }
            }

            if (entrypoints.isEmpty()) {
                System.out.println("  No methods found in target class: " + targetClassName);
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

            // Check if any CWE has sinks (now tainted sinks)
            boolean hasAnyPath = false;
            for (String cweId : cweSources.keySet()) {
                if (foundSourcesPerCWE.containsKey(cweId) && !foundSourcesPerCWE.get(cweId).isEmpty() &&
                        foundSinksPerCWE.containsKey(cweId) && !foundSinksPerCWE.get(cweId).isEmpty()) {
                    hasAnyPath = true;
                    System.out.println("  Found sources and tainted sinks for " + cweId);
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

        DefUse du = node.getDU();

        for (String cweId : cweSources.keySet()) {
            Set<Integer> tainted = new HashSet<>();
            Queue<Integer> workList = new LinkedList<>();

            // Find sources for this CWE
            for (int idx = 0; idx < ir.getInstructions().length; idx++) {
                SSAInstruction inst = ir.getInstructions()[idx];
                if (inst == null || !(inst instanceof SSAInvokeInstruction)) continue;

                SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;

                String sig = invoke.getDeclaredTarget().getSignature();

                List<String> sources = cweSources.get(cweId);
                if (sources != null && sources.contains(sig)) {

                    if (invoke.hasDef()) {
                        int def = invoke.getDef();
                        if (!tainted.contains(def)) {
                            tainted.add(def);
                            workList.add(def);
                        }
                    }

                    // Record source
                    int ssaIndex = inst.iIndex();
                    int bytecodeIndex = ir.getControlFlowGraph().getProgramCounter(ssaIndex);
                    int line = (bytecodeIndex >= 0) ? node.getMethod().getLineNumber(bytecodeIndex) : -1;
                    String sourceFile = node.getMethod().getDeclaringClass().getSourceFileName();

                    String methodName = invoke.getDeclaredTarget().getName().toString();
                    String className = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
                    String containingMethod = node.getMethod().getName().toString();
                    String containingClassName = node.getMethod().getDeclaringClass().getName().toString();

                    foundSourcesPerCWE.computeIfAbsent(cweId, k -> new ArrayList<>())
                            .add(new TaintElement(cweId, methodName, className, containingMethod, containingClassName, sourceFile, line));
                    System.out.println("    Found source for " + cweId + ": " + sig +
                            " in " + containingMethod + " at line " + line);
                }
            }

            // Propagate taint for this CWE
            List<String> sanitizers = cweSanitizers.getOrDefault(cweId, Collections.emptyList());

            while (!workList.isEmpty()) {
                int v = workList.poll();
                Iterator<SSAInstruction> uses = du.getUses(v);
                while (uses.hasNext()) {
                    SSAInstruction useInst = uses.next();

                    // Propagate to def if applicable
                    if (useInst.hasDef()) {
                        boolean propagates = true;
                        if (useInst instanceof SSAInvokeInstruction) {
                            SSAInvokeInstruction invoke = (SSAInvokeInstruction) useInst;
                            String sig = invoke.getDeclaredTarget().getSignature();
                            if (sanitizers.contains(sig)) {
                                propagates = false;
                            }
                        }
                        if (propagates) {
                            int def = useInst.getDef();
                            if (!tainted.contains(def)) {
                                tainted.add(def);
                                workList.add(def);
                            }
                        }
                    }

                    // Special handling for constructors
                    if (useInst instanceof SSAInvokeInstruction) {
                        SSAInvokeInstruction invoke = (SSAInvokeInstruction) useInst;
                        if (invoke.getDeclaredTarget().isInit()) {
                            boolean paramTainted = false;
                            for (int p = 1; p < invoke.getNumberOfUses(); p++) {
                                if (invoke.getUse(p) == v) {
                                    paramTainted = true;
                                    break;
                                }
                            }
                            if (paramTainted) {
                                int receiver = invoke.getUse(0);
                                if (!tainted.contains(receiver)) {
                                    tainted.add(receiver);
                                    workList.add(receiver);
                                }
                            }
                        }
                    }

                    // Check for sinks for this CWE
                    if (useInst instanceof SSAInvokeInstruction) {
                        SSAInvokeInstruction invoke = (SSAInvokeInstruction) useInst;
                        String sig = invoke.getDeclaredTarget().getSignature();
                        List<String> sinks = cweSinks.get(cweId);
                        if (sinks != null && sinks.contains(sig)) {
                            boolean isArg = false;
                            int start = invoke.isStatic() ? 0 : 1;
                            for (int p = start; p < invoke.getNumberOfUses(); p++) {
                                if (invoke.getUse(p) == v) {
                                    isArg = true;
                                    break;
                                }
                            }
                            if (isArg) {
                                // Tainted sink found
                                int ssaIndex = useInst.iIndex();
                                int bytecodeIndex = ir.getControlFlowGraph().getProgramCounter(ssaIndex);
                                int line = (bytecodeIndex >= 0) ? node.getMethod().getLineNumber(bytecodeIndex) : -1;
                                String sourceFile = node.getMethod().getDeclaringClass().getSourceFileName();

                                String methodName = invoke.getDeclaredTarget().getName().toString();
                                String className = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
                                String containingMethod = node.getMethod().getName().toString();
                                String containingClassName = node.getMethod().getDeclaringClass().getName().toString();

                                foundSinksPerCWE.computeIfAbsent(cweId, k -> new ArrayList<>())
                                        .add(new TaintElement(cweId, methodName, className, containingMethod, containingClassName, sourceFile, line));
                                System.out.println("    Found tainted sink for " + cweId + ": " + sig +
                                        " in " + containingMethod + " at line " + line);
                            }
                        }
                    }
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