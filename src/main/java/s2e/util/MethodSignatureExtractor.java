package s2e.util;

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
        CompilationUnit cu = parser.parse(file).getResult()
                .orElseThrow(() -> new RuntimeException("Parse failed"));

        String packageName = cu.getPackageDeclaration()
                .map(pd -> pd.getNameAsString()).orElse("");

        List<String> signatures = new ArrayList<>();

        for (ClassOrInterfaceDeclaration clazz : cu.findAll(ClassOrInterfaceDeclaration.class)) {
            String className = clazz.getNameAsString();
            String fqcn = (packageName.isEmpty() ? className : packageName + "." + className);

            for (MethodDeclaration method : clazz.getMethods()) {
                StringBuilder sig = new StringBuilder(fqcn + "." + method.getNameAsString() + "(");

                for (var param : method.getParameters()) {
                    sig.append(jvmTypeDescriptor(param.getType().asString()));
                }

                sig.append(")").append(jvmTypeDescriptor(method.getType().asString()));
                signatures.add(sig.toString());
            }
        }
        return signatures;
    }

    public static String jvmTypeDescriptor(String type) {
        switch (type) {
            case "int": return "I";
            case "boolean": return "Z";
            case "long": return "J";
            case "double": return "D";
            case "float": return "F";
            case "void": return "V";
            case "String": return "Ljava/lang/String;";
            default:
                if (type.endsWith("[]")) {
                    return "[" + jvmTypeDescriptor(type.substring(0, type.length() - 2));
                }
                return "L" + type.replace('.', '/') + ";";
        }
    }

    public static String getFullyQualifiedClassName(String javaFile) throws Exception {
        File file = new File(javaFile);
        JavaParser parser = new JavaParser();
        CompilationUnit cu = parser.parse(file).getResult()
                .orElseThrow(() -> new RuntimeException("Parse failed"));

        String packageName = cu.getPackageDeclaration()
                .map(pd -> pd.getNameAsString()).orElse("");
        String className = cu.getPrimaryTypeName()
                .orElseThrow(() -> new RuntimeException("No class found"));

        return packageName.isEmpty() ? className : packageName + "." + className;
    }
}