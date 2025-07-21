package s2e.taint;

public class TaintElement {
    public String cweId;
    public String methodName;
    public String className;
    public String containingMethod;
    public String containingClassName;
    public String sourceFileName;
    public int line;

    public TaintElement(String cweId, String methodName, String className,
                        String containingMethod, String containingClassName,
                        String sourceFileName, int line) {
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