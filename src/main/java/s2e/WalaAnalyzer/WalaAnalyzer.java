package s2e.WalaAnalyzer;

import com.ibm.wala.classLoader.*;
import com.ibm.wala.ipa.callgraph.*;
import com.ibm.wala.ipa.cha.ClassHierarchyFactory;
import com.ibm.wala.ipa.cha.ClassHierarchy;
import com.ibm.wala.core.util.config.AnalysisScopeReader;
import com.ibm.wala.types.ClassLoaderReference;

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
            "nextLine", "getParameter", "getHeader", "readLine", "getInputStream", "args"
    );
    private static final List<String> SINKS = Arrays.asList(
            "System.setProperty", "System.setenv", "System.clearProperty"
    );

    /**
     * Analyze taint for ALL compiled class files in the class directories + dependencies.
     *
     * @param classDirs List of directories containing .class files (testcasesupport, testcases, etc)
     * @param jarPaths List of absolute paths to dependency .jar files (can be empty)
     * @return List of TaintResult for user-controlled data leading to dangerous sinks
     */
    public static List<TaintResult> analyzeTaint(List<String> classDirs, List<String> jarPaths) throws Exception {
        List<TaintResult> results = new ArrayList<>();

        // --- 1. Scope Build ---
        System.out.println("=== Building AnalysisScope ===");
        // Use first dir as base for AnalysisScope
        String baseDir = classDirs.get(0);
        AnalysisScope scope = AnalysisScopeReader.instance.makeJavaBinaryAnalysisScope(baseDir, null);

        // --- 2. Add class directories ---
        for (String classDir : classDirs) {
            File dir = new File(classDir);
            if (dir.exists() && dir.isDirectory()) {
                System.out.println("  Adding class directory: " + classDir);
                scope.addToScope(ClassLoaderReference.Application, new BinaryDirectoryTreeModule(dir));
            } else {
                System.out.println("  (Skip) Not a class dir: " + classDir);
            }
        }

        // --- 3. Add jars ---
        for (String jarPath : jarPaths) {
            File jarFile = new File(jarPath);
            if (jarFile.exists() && jarFile.isFile() && jarPath.endsWith(".jar")) {
                System.out.println("  Adding JAR: " + jarPath);
                scope.addToScope(ClassLoaderReference.Application, new JarFile(jarFile));
            } else {
                System.out.println("  (Skip) Not found or not a JAR: " + jarPath);
            }
        }

        // --- 4. ClassHierarchy ---
        ClassHierarchy cha = ClassHierarchyFactory.make(scope);
        System.out.println("=== Classes loaded in ClassHierarchy ===");
        for (IClass klass : cha) {
            System.out.println("  " + klass.getName());
        }

        // --- 5. Entrypoints ---
        Iterable<Entrypoint> entrypoints = com.ibm.wala.ipa.callgraph.impl.Util.makeMainEntrypoints(cha);
        int epCount = 0;
        for (Entrypoint ep : entrypoints) {
            System.out.println("Entrypoint: " + ep);
            epCount++;
        }
        if (epCount == 0) {
            throw new RuntimeException("No valid entrypoints (main methods) found in loaded classes!");
        }

        // --- 6. Build Call Graph ---
        AnalysisOptions options = new AnalysisOptions(scope, entrypoints);
        IAnalysisCacheView cache = new com.ibm.wala.ipa.callgraph.AnalysisCacheImpl();

        CallGraphBuilder<?> builder = com.ibm.wala.ipa.callgraph.impl.Util.makeZeroCFABuilder(
                Language.JAVA, options, cache, cha, scope);
        CallGraph cg = builder.makeCallGraph(options, null);

        System.out.println("=== Methods found in CallGraph ===");
        int methodCount = 0;
        for (CGNode node : cg) {
            System.out.println("  " + node.getMethod());
            methodCount++;
        }
        if (methodCount == 0) {
            System.out.println("No methods found in CallGraph! Exiting...");
            return results;
        }

        // --- 7. Per-Method IR Debug ---
        for (CGNode node : cg) {
            if (node.getIR() == null) continue;
            System.out.println("Processing " + node.getMethod() + " ...");
            for (int i = 0; i < node.getIR().getInstructions().length; i++) {
                String instr = node.getIR().getInstructions()[i] != null
                        ? node.getIR().getInstructions()[i].toString() : "";
                System.out.println("    IR " + i + ": " + instr);
            }
        }

        // === Existing analysis logic goes here ===

        return results;
    }

}