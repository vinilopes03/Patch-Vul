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

    // Collect details per entrypoint method
    private final Map<String, Map<String, List<TaintElement>>> foundSourcesByEntry = new HashMap<>();
    private final Map<String, Map<String, List<TaintElement>>> foundSinksByEntry = new HashMap<>();

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

    public static class Pair<A, B> {
        A first;
        B second;

        public Pair(A first, B second) {
            this.first = first;
            this.second = second;
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

            // Reset collections
            foundSourcesByEntry.clear();
            foundSinksByEntry.clear();

            // Base options and cache
            AnalysisOptions baseOptions = new AnalysisOptions(scope, null);
            baseOptions.setReflectionOptions(AnalysisOptions.ReflectionOptions.NONE);
            IAnalysisCacheView cache = new AnalysisCacheImpl();

            boolean hasAnyPath = false;

            // Analyze per entrypoint
            for (Entrypoint ep : entrypoints) {
                String entryMethod = ep.getMethod().getName().toString();
                System.out.println("  Analyzing from entrypoint: " + entryMethod);

                AnalysisOptions options = new AnalysisOptions(scope, Collections.singleton(ep));
                options.setReflectionOptions(AnalysisOptions.ReflectionOptions.NONE);

                CallGraphBuilder<?> builder = Util.makeZeroCFABuilder(
                        Language.JAVA, options, cache, cha
                );

                CallGraph cg = builder.makeCallGraph(options, null);
                System.out.println("    Call graph for " + entryMethod + " built with " + cg.getNumberOfNodes() + " nodes");

                for (String cweId : cweSources.keySet()) {
                    if (performTaintAnalysisForCWE(cweId, cg, cha, entryMethod)) {
                        hasAnyPath = true;
                        System.out.println("    Found sources and tainted sinks for " + cweId + " from " + entryMethod);
                    }
                }
            }

            return hasAnyPath;

        } catch (Exception e) {
            System.err.println("Simplified taint analysis failed: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    private boolean performTaintAnalysisForCWE(String cweId, CallGraph cg, ClassHierarchy cha, String entryMethod) {
        List<String> sources = cweSources.get(cweId);
        List<String> sinks = cweSinks.get(cweId);
        List<String> sanitizers = cweSanitizers.getOrDefault(cweId, Collections.emptyList());

        Map<CGNode, Set<Integer>> tainted = new HashMap<>();
        Queue<Pair<CGNode, Integer>> worklist = new LinkedList<>();

        // Seed sources
        for (CGNode node : cg) {
            if (!isApplicationClass(node)) continue;

            IR ir = node.getIR();
            if (ir == null) continue;

            tainted.put(node, new HashSet<>());

            for (SSAInstruction inst : ir.getInstructions()) {
                if (inst == null || !(inst instanceof SSAInvokeInstruction)) continue;

                SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
                String sig = invoke.getDeclaredTarget().getSignature();

                if (sources.contains(sig) && invoke.hasDef()) {
                    int def = invoke.getDef();
                    tainted.get(node).add(def);
                    worklist.add(new Pair<>(node, def));

                    // Record source per entry
                    int ssaIndex = inst.iIndex();
                    int bytecodeIndex = ir.getControlFlowGraph().getProgramCounter(ssaIndex);
                    int line = (bytecodeIndex >= 0) ? node.getMethod().getLineNumber(bytecodeIndex) : -1;
                    String sourceFile = node.getMethod().getDeclaringClass().getSourceFileName();

                    String methodName = invoke.getDeclaredTarget().getName().toString();
                    String className = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
                    String containingMethod = node.getMethod().getName().toString();
                    String containingClassName = node.getMethod().getDeclaringClass().getName().toString();

                    Map<String, List<TaintElement>> sourcesForEntry = foundSourcesByEntry.computeIfAbsent(entryMethod, k -> new HashMap<>());
                    sourcesForEntry.computeIfAbsent(cweId, k -> new ArrayList<>())
                            .add(new TaintElement(cweId, methodName, className, containingMethod, containingClassName, sourceFile, line));
                    System.out.println("      Found source for " + cweId + ": " + sig +
                            " in " + containingMethod + " at line " + line);
                }
            }
        }

        // Propagate taint
        while (!worklist.isEmpty()) {
            Pair<CGNode, Integer> item = worklist.poll();
            CGNode node = item.first;
            int v = item.second;

            IR ir = node.getIR();
            if (ir == null) continue;

            DefUse du = node.getDU();

            Iterator<SSAInstruction> uses = du.getUses(v);
            while (uses.hasNext()) {
                SSAInstruction useInst = uses.next();

                // Propagate to def
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
                        Set<Integer> nodeTainted = tainted.get(node);
                        if (!nodeTainted.contains(def)) {
                            nodeTainted.add(def);
                            worklist.add(new Pair<>(node, def));
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
                            Set<Integer> nodeTainted = tainted.get(node);
                            if (!nodeTainted.contains(receiver)) {
                                nodeTainted.add(receiver);
                                worklist.add(new Pair<>(node, receiver));
                            }
                        }
                    }
                }

                // Check for sinks
                if (useInst instanceof SSAInvokeInstruction) {
                    SSAInvokeInstruction invoke = (SSAInvokeInstruction) useInst;
                    String sig = invoke.getDeclaredTarget().getSignature();
                    if (sinks.contains(sig)) {
                        boolean isArg = false;
                        int start = invoke.isStatic() ? 0 : 1;
                        for (int p = start; p < invoke.getNumberOfUses(); p++) {
                            if (invoke.getUse(p) == v) {
                                isArg = true;
                                break;
                            }
                        }
                        if (isArg) {
                            // Record tainted sink per entry
                            int ssaIndex = useInst.iIndex();
                            int bytecodeIndex = ir.getControlFlowGraph().getProgramCounter(ssaIndex);
                            int line = (bytecodeIndex >= 0) ? node.getMethod().getLineNumber(bytecodeIndex) : -1;
                            String sourceFile = node.getMethod().getDeclaringClass().getSourceFileName();

                            String methodName = invoke.getDeclaredTarget().getName().toString();
                            String className = invoke.getDeclaredTarget().getDeclaringClass().getName().toString();
                            String containingMethod = node.getMethod().getName().toString();
                            String containingClassName = node.getMethod().getDeclaringClass().getName().toString();

                            Map<String, List<TaintElement>> sinksForEntry = foundSinksByEntry.computeIfAbsent(entryMethod, k -> new HashMap<>());
                            sinksForEntry.computeIfAbsent(cweId, k -> new ArrayList<>())
                                    .add(new TaintElement(cweId, methodName, className, containingMethod, containingClassName, sourceFile, line));
                            System.out.println("      Found tainted sink for " + cweId + ": " + sig +
                                    " in " + containingMethod + " at line " + line);
                        }
                    }
                }

                // Propagate to callees (parameters)
                if (useInst instanceof SSAInvokeInstruction) {
                    SSAInvokeInstruction invoke = (SSAInvokeInstruction) useInst;
                    int useIndex = -1;
                    for (int p = 0; p < invoke.getNumberOfUses(); p++) {
                        if (invoke.getUse(p) == v) {
                            useIndex = p;
                            break;
                        }
                    }
                    if (useIndex != -1) {
                        CallSiteReference site = invoke.getCallSite();
                        Iterator<CGNode> calleeIt = cg.getPossibleTargets(node, site).iterator();
                        while (calleeIt.hasNext()) {
                            CGNode callee = calleeIt.next();
                            if (!isApplicationClass(callee)) continue;

                            IR calleeIR = callee.getIR();
                            if (calleeIR == null) continue;

                            tainted.computeIfAbsent(callee, k -> new HashSet<>());

                            boolean isStatic = invoke.isStatic();
                            if (useIndex == 0 && !isStatic) {
                                // Receiver
                                int receiverSSA = 1;
                                Set<Integer> calleeTainted = tainted.get(callee);
                                if (!calleeTainted.contains(receiverSSA)) {
                                    calleeTainted.add(receiverSSA);
                                    worklist.add(new Pair<>(callee, receiverSSA));
                                }
                            } else {
                                // Parameter
                                int paramNum = useIndex - (isStatic ? 0 : 1);
                                int paramSSA = (callee.getMethod().isStatic() ? 1 : 2) + paramNum;
                                Set<Integer> calleeTainted = tainted.get(callee);
                                if (!calleeTainted.contains(paramSSA)) {
                                    calleeTainted.add(paramSSA);
                                    worklist.add(new Pair<>(callee, paramSSA));
                                }
                            }
                        }
                    }
                }

                // Propagate from returns to callers
                if (useInst instanceof SSAReturnInstruction) {
                    SSAReturnInstruction retInst = (SSAReturnInstruction) useInst;
                    if (retInst.getResult() == v) {
                        Iterator<CGNode> callerIt = cg.getPredNodes(node);
                        while (callerIt.hasNext()) {
                            CGNode caller = callerIt.next();
                            if (!isApplicationClass(caller)) continue;

                            tainted.computeIfAbsent(caller, k -> new HashSet<>());

                            IR callerIR = caller.getIR();
                            if (callerIR == null) continue;

                            for (Iterator<CallSiteReference> siteIt = callerIR.iterateCallSites(); siteIt.hasNext(); ) {
                                CallSiteReference cs = siteIt.next();
                                Set<CGNode> targets = cg.getPossibleTargets(caller, cs);
                                if (targets.contains(node)) {
                                    SSAInstruction invokeInst = null;
                                    for (SSAInstruction inst : callerIR.getInstructions()) {
                                        if (inst instanceof SSAInvokeInstruction) {
                                            SSAInvokeInstruction invoke = (SSAInvokeInstruction) inst;
                                            if (invoke.getCallSite().equals(cs)) {
                                                invokeInst = invoke;
                                                break;
                                            }
                                        }
                                    }
                                    if (invokeInst != null && ((SSAInvokeInstruction) invokeInst).hasDef()) {
                                        int cdef = ((SSAInvokeInstruction) invokeInst).getDef();
                                        Set<Integer> callerTainted = tainted.get(caller);
                                        if (!callerTainted.contains(cdef)) {
                                            callerTainted.add(cdef);
                                            worklist.add(new Pair<>(caller, cdef));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Map<String, List<TaintElement>> sourcesForEntry = foundSourcesByEntry.getOrDefault(entryMethod, new HashMap<>());
        Map<String, List<TaintElement>> sinksForEntry = foundSinksByEntry.getOrDefault(entryMethod, new HashMap<>());

        return sourcesForEntry.containsKey(cweId) && !sourcesForEntry.get(cweId).isEmpty() &&
                sinksForEntry.containsKey(cweId) && !sinksForEntry.get(cweId).isEmpty();
    }

    // Getters for reporting
    public Map<String, Map<String, List<TaintElement>>> getFoundSinksByEntryPerCWE() {
        return foundSinksByEntry;
    }

    public Map<String, Map<String, List<TaintElement>>> getFoundSourcesByEntryPerCWE() {
        return foundSourcesByEntry;
    }

    private boolean isApplicationClass(CGNode node) {
        return node.getMethod().getDeclaringClass().getClassLoader()
                .getReference().equals(ClassLoaderReference.Application);
    }
}