package s2e.PatchGenerator;

public class ToJson {
    public String filePath;  // Full or relative path
    public int line;
    public String cwe;

    public ToJson(String file, int line, String cwe) {
        this.filePath = file;
        this.line = line;
        this.cwe = cwe;
    }
}
