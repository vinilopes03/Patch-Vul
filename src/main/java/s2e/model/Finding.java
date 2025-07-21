package s2e.model;

public class Finding {
    public String filePath;
    public int line;
    public String cwe;

    public Finding(String filePath, int line, String cwe) {
        this.filePath = filePath;
        this.line = line;
        this.cwe = cwe;
    }
}