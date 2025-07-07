package s2e.PatchGenerator;

import s2e.Scanner.VulnerabilityScanner;
import java.io.File;
import java.util.*;

public class Main {
    public static void main(String[] args) throws Exception {
        String javaFile = "/Users/vlopes/Desktop/Java/src/testcases/CWE15_External_Control_of_System_or_Configuration_Setting/CWE15_External_Control_of_System_or_Configuration_Setting__Environment_54a.java";
        String patternFile = "/Users/vlopes/Desktop/git-projects/PatchVul/src/main/resources/PatchPattern.json";
        String supportFilesDir = "/Users/vlopes/Desktop/Java/src/testcasesupport";
        String classDir = "/Users/vlopes/Desktop/Java/src/testcases/CWE15_External_Control_of_System_or_Configuration_Setting";
        String jarDir = "/Users/vlopes/Desktop/Java/lib/";

        // Separate .jar files and support directories
        List<String> jarPaths = new ArrayList<>();
        List<String> classDirs = new ArrayList<>();
        classDirs.add(supportFilesDir);

        File dir = new File(jarDir);
        File[] jarFiles = dir.listFiles((d, name) -> name.endsWith(".jar"));
        if (jarFiles != null) {
            for (File jar : jarFiles) {
                jarPaths.add(jar.getAbsolutePath());
            }
        }

        VulnerabilityScanner scanner = new VulnerabilityScanner(patternFile);
        scanner.scan(javaFile, classDir, classDirs, jarPaths);  // pass both lists!
        VulnerabilityScanner.exportFindingsToJson(scanner.getFindings(), "findings.json");
    }
}