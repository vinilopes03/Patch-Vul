package s2e.Utils; // (Or your chosen package)

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class MethodSignatureExtractor {
    public static List<String> extractMethodSignatures(String javaFile) throws Exception {
        File file = new File(javaFile);
        JavaParser parser = new JavaParser();
        CompilationUnit cu = parser.parse(file).getResult().orElseThrow(() -> new RuntimeException("Parse failed"));
        String packageName = cu.getPackageDeclaration().map(pd -> pd.getNameAsString()).orElse("");
        List<String> signatures = new ArrayList<>();
        for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            String className = clazz.getNameAsString();
            String fqcn = (packageName.isEmpty() ? className : packageName + "." + className);
            for (MethodDeclaration m : clazz.getMethods()) {
                StringBuilder sig = new StringBuilder(fqcn + "." + m.getNameAsString() + "(");
                for (var p : m.getParameters()) {
                    sig.append(jvmTypeDescriptor(p.getType().asString()));
                }
                sig.append(")").append(jvmTypeDescriptor(m.getType().asString()));
                signatures.add(sig.toString());
            }
        }
        return signatures;
    }

    // Basic JVM descriptor mapping
    public static String jvmTypeDescriptor(String t) {
        switch (t) {
            case "int": return "I";
            case "boolean": return "Z";
            case "long": return "J";
            case "double": return "D";
            case "float": return "F";
            case "void": return "V";
            case "String": return "Ljava/lang/String;";
            default:
                if (t.endsWith("[]")) return "[" + jvmTypeDescriptor(t.substring(0, t.length()-2));
                return "L" + t.replace('.', '/') + ";";
        }
    }

    public static String getFullyQualifiedClassName(String javaFile) throws Exception {
        File file = new File(javaFile);
        JavaParser parser = new JavaParser();
        CompilationUnit cu = parser.parse(file).getResult().orElseThrow(() -> new RuntimeException("Parse failed"));
        String packageName = cu.getPackageDeclaration().map(pd -> pd.getNameAsString()).orElse("");
        String className = cu.getPrimaryTypeName().orElseThrow(() -> new RuntimeException("No class found"));
        return packageName.isEmpty() ? className : packageName + "." + className;
    }
}