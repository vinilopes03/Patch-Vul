package s2e.PatternAnalyzer;
import com.google.gson.*;


import java.io.FileReader;


public class PatternLoader {
    private final JsonObject patterns;

    public PatternLoader(String jsonPath) throws Exception {
        System.out.println("Loading patterns from " + jsonPath);
        patterns = JsonParser.parseReader(new FileReader(jsonPath)).getAsJsonObject();
    }

    public JsonObject getPatterns() {
        return patterns;
    }
}
