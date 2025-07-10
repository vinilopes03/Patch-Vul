package s2e.PatchGenerator;

import s2e.Scanner.VulnerabilityScanner;
import java.io.File;
import java.util.*;

public class Main {
    public static void main(String[] args) throws Exception {
        String javaFile = "/Users/vlopes/Desktop/Java/src/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__Environment_54c.java";
        String patternFile = "/Users/vlopes/Desktop/git-projects/PatchVul/src/main/resources/PatchPattern.json";
        String supportFilesDir = "/Users/vlopes/Desktop/Java/src/testcasesupport";
        String classDir = "/Users/vlopes/Desktop/Java/src/testcases/CWE15_External_Control_of_System_or_Configuration_Setting";
        String jarDir = "/Users/vlopes/Desktop/Java/lib/";

        // Check if files exist
        File javaFileObj = new File(javaFile);
        File patternFileObj = new File(patternFile);

        if (!javaFileObj.exists()) {
            System.err.println("Java file not found: " + javaFile);
            return;
        }
        if (!patternFileObj.exists()) {
            System.err.println("Pattern file not found: " + patternFile);
            return;
        }

        // Separate .jar files and support directories
        List<String> jarPaths = new ArrayList<>();
        List<String> classDirs = new ArrayList<>();
        classDirs.add(supportFilesDir);

        // Add all JAR files from the jar directory
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

        System.out.println("\n========================================");
        System.out.println("VULNERABILITY SCANNER - CWE Detection");
        System.out.println("========================================");
        System.out.println("Target file: " + javaFile);
        System.out.println("Pattern file: " + patternFile);
        System.out.println("Class directory: " + classDir);
        System.out.println("Support files: " + supportFilesDir);
        System.out.println("========================================\n");

        VulnerabilityScanner scanner = new VulnerabilityScanner(patternFile);
        scanner.scan(javaFile, classDir, classDirs, jarPaths);

        // Export findings
        VulnerabilityScanner.exportFindingsToJson(scanner.getFindings(), "findings.json");

        // Print summary
        System.out.println("\n========================================");
        System.out.println("FINAL RESULTS");
        System.out.println("========================================");
        if (scanner.getFindings().isEmpty()) {
            System.out.println("No vulnerabilities detected.");
        } else {
            System.out.println("Found " + scanner.getFindings().size() + " vulnerability(ies):\n");
            for (ToJson finding : scanner.getFindings()) {
                System.out.println(String.format("  • %s at line %d", finding.cwe, finding.line));
                System.out.println("    File: " + finding.filePath);
                System.out.println();
            }
        }
    }
}