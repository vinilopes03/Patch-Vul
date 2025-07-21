package s2e;

import s2e.model.Finding;
import s2e.scanner.VulnerabilityScanner;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) throws Exception {
        String javaFile = "/Users/vlopes/Desktop/Java/src/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__Environment_54a.java";
        String patternFile = "/Users/vlopes/Desktop/git-projects/Patch-Vul/src/main/resources/patterns/cwe-patterns.json";
        String supportFilesDir = "/Users/vlopes/Desktop/Java/src/testcasesupport";
        String classDir = "/Users/vlopes/Desktop/Java/src/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/";
        String jarDir = "/Users/vlopes/Desktop/Java/lib/";
        String exclusionsFile = "/Users/vlopes/Desktop/git-projects/Patch-Vul/src/main/resources/config/exclusions.txt";

        if (!validateFiles(javaFile, patternFile, exclusionsFile)) {
            return;
        }

        List<String> jarPaths = loadJarFiles(jarDir);
        List<String> classDirs = createClassDirsList(supportFilesDir);

        printHeader(javaFile, patternFile, classDir, supportFilesDir, exclusionsFile);

        VulnerabilityScanner scanner = new VulnerabilityScanner(patternFile);
        scanner.scan(javaFile, classDir, classDirs, jarPaths);

        VulnerabilityScanner.exportFindingsToJson(scanner.getFindings(), "findings.json");
        printResults(scanner.getFindings());
    }

    private static boolean validateFiles(String javaFile, String patternFile, String exclusionsFile) {
        File javaFileObj = new File(javaFile);
        File patternFileObj = new File(patternFile);
        File exclusionsFileObj = new File(exclusionsFile);

        if (!javaFileObj.exists()) {
            System.err.println("Java file not found: " + javaFile);
            return false;
        }
        if (!patternFileObj.exists()) {
            System.err.println("Pattern file not found: " + patternFile);
            return false;
        }
        if (!exclusionsFileObj.exists()) {
            System.err.println("Exclusions file not found: " + exclusionsFile);
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
                    System.out.println("Adding JAR: " + jar.getName());
                }
            }
        }
        return jarPaths;
    }

    private static List<String> createClassDirsList(String supportFilesDir) {
        List<String> classDirs = new ArrayList<>();
        classDirs.add(supportFilesDir);
        return classDirs;
    }

    private static void printHeader(String javaFile, String patternFile, String classDir,
                                    String supportFilesDir, String exclusionsFile) {
        System.out.println("\n========================================");
        System.out.println("VULNERABILITY SCANNER - CWE Detection");
        System.out.println("========================================");
        System.out.println("Target file: " + javaFile);
        System.out.println("Pattern file: " + patternFile);
        System.out.println("Class directory: " + classDir);
        System.out.println("Support files: " + supportFilesDir);
        System.out.println("Exclusions file: " + exclusionsFile);
        System.out.println("========================================\n");
    }

    private static void printResults(List<Finding> findings) {
        System.out.println("\n========================================");
        System.out.println("FINAL RESULTS");
        System.out.println("========================================");

        if (findings.isEmpty()) {
            System.out.println("No vulnerabilities detected.");
        } else {
            System.out.println("Found " + findings.size() + " vulnerability(ies):\n");
            for (Finding finding : findings) {
                System.out.println(String.format("  • %s at line %d", finding.cwe, finding.line));
                System.out.println("    File: " + finding.filePath);
                System.out.println();
            }
        }
    }
}