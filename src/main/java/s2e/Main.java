package s2e;

import s2e.model.Finding;
import s2e.scanner.VulnerabilityScanner;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        // Check if we have enough arguments for pipeline mode
        if (args.length >= 7) {
            // Pipeline mode: java s2e.Main <javaFile> <patternFile> <supportFilesDir> <classDir> <jarDir> <exclusionsFile> <outputFile>
            runPipelineMode(args);
        } else if (args.length == 0) {
        } else {
            System.err.println("Usage: java s2e.Main <javaFile> <patternFile> <supportFilesDir> <classDir> <jarDir> <exclusionsFile> <outputFile>");
            System.err.println("   OR: java s2e.Main (for test mode with hardcoded paths)");
            System.exit(1);
        }
    }

    private static void runPipelineMode(String[] args) throws Exception {
        String javaFile = args[0];
        String patternFile = args[1];
        String supportFilesDir = args[2];
        String classDir = args[3];
        String jarDir = args[4];
        String exclusionsFile = args[5];
        String outputFile = args[6];

        System.out.println("🚀 Running S2E Scanner in Pipeline Mode");
        runScanner(javaFile, patternFile, supportFilesDir, classDir, jarDir, exclusionsFile, outputFile);
    }

    private static void runScanner(String javaFile, String patternFile, String supportFilesDir,
                                   String classDir, String jarDir, String exclusionsFile, String outputFile) throws Exception {

        if (!validateFiles(javaFile, patternFile, exclusionsFile)) {
            System.exit(1);
        }

        List<String> jarPaths = loadJarFiles(jarDir);
        List<String> classDirs = createClassDirsList(supportFilesDir);

        printHeader(javaFile, patternFile, classDir, supportFilesDir, exclusionsFile, outputFile);

        VulnerabilityScanner scanner = new VulnerabilityScanner(patternFile);
        scanner.scan(javaFile, classDir, classDirs, jarPaths);  // Keep same order as working version

        // Export findings to specified output file
        VulnerabilityScanner.exportFindingsToJson(scanner.getFindings(), outputFile);
        printResults(scanner.getFindings(), outputFile);
    }

    private static boolean validateFiles(String javaFile, String patternFile, String exclusionsFile) {
        File javaFileObj = new File(javaFile);
        File patternFileObj = new File(patternFile);
        File exclusionsFileObj = new File(exclusionsFile);

        if (!javaFileObj.exists()) {
            System.err.println("❌ Java file not found: " + javaFile);
            return false;
        }
        if (!patternFileObj.exists()) {
            System.err.println("❌ Pattern file not found: " + patternFile);
            return false;
        }
        if (!exclusionsFileObj.exists()) {
            System.err.println("❌ Exclusions file not found: " + exclusionsFile);
            return false;
        }
        return true;
    }

    private static List<String> loadJarFiles(String jarDir) {
        List<String> jarPaths = new ArrayList<>();
        File jarDirFile = new File(jarDir);

        if (jarDirFile.exists() && jarDirFile.isDirectory()) {
            File[] jarFiles = jarDirFile.listFiles((d, name) -> name.endsWith(".jar"));
            if (jarFiles != null) {
                for (File jar : jarFiles) {
                    jarPaths.add(jar.getAbsolutePath());
                    System.out.println("📦 Adding JAR: " + jar.getName());
                }
            }
        } else {
            System.out.println("⚠️  JAR directory not found or not a directory: " + jarDir);
        }
        return jarPaths;
    }

    private static List<String> createClassDirsList(String supportFilesDir) {
        List<String> classDirs = new ArrayList<>();
        if (new File(supportFilesDir).exists()) {
            classDirs.add(supportFilesDir);
            System.out.println("📁 Adding support files directory: " + supportFilesDir);
        } else {
            System.out.println("⚠️  Support files directory not found: " + supportFilesDir);
        }
        return classDirs;
    }

    private static void printHeader(String javaFile, String patternFile, String classDir,
                                    String supportFilesDir, String exclusionsFile, String outputFile) {
        System.out.println("\n========================================");
        System.out.println("VULNERABILITY SCANNER - CWE Detection");
        System.out.println("========================================");
        System.out.println("Target file: " + javaFile);
        System.out.println("Pattern file: " + patternFile);
        System.out.println("Class directory: " + classDir);
        System.out.println("Support files: " + supportFilesDir);
        System.out.println("Exclusions file: " + exclusionsFile);
        System.out.println("Output file: " + outputFile);
        System.out.println("========================================\n");
    }

    private static void printResults(List<Finding> findings, String outputFile) {
        System.out.println("\n========================================");
        System.out.println("FINAL RESULTS");
        System.out.println("========================================");

        if (findings.isEmpty()) {
            System.out.println("✅ No vulnerabilities detected.");
        } else {
            System.out.println("🔍 Found " + findings.size() + " vulnerability(ies):\n");
            for (Finding finding : findings) {
                System.out.println(String.format("  • %s at line %d", finding.cwe, finding.line));
                System.out.println("    File: " + finding.filePath);
                System.out.println();
            }
        }

        System.out.println("📋 Results exported to: " + outputFile);
        System.out.println("========================================");
    }
}