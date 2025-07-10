package s2e.TaintAnalysis;

import java.util.*;

/**
 * Configuration for CWE sources and sinks
 */
public class CweConfiguration {
    private final Map<String, List<String>> cweSources = new HashMap<>();
    private final Map<String, List<String>> cweSinks = new HashMap<>();

    public CweConfiguration() {
        initializeSourcesAndSinks();
    }

    private void initializeSourcesAndSinks() {
        // CWE-15: External Control of System Setting
        cweSources.put("CWE-15", Arrays.asList("getenv"));
        cweSinks.put("CWE-15", Arrays.asList(
                "setProperty", "clearProperty", "setCatalog",
                "setSchema", "setSessionContext", "setLogWriter",
                "setLoginTimeout", "lookup", "setRequestProperty",
                "addRequestProperty"
        ));

        // CWE-78: OS Command Injection
        cweSources.put("CWE-78", Arrays.asList("getParameter", "readLine", "nextLine"));
        cweSinks.put("CWE-78", Arrays.asList("exec"));

        // CWE-89: SQL Injection
        cweSources.put("CWE-89", Arrays.asList("getParameter", "readLine", "nextLine"));
        cweSinks.put("CWE-89", Arrays.asList("executeQuery", "executeUpdate", "execute"));

        // CWE-80: XSS
        cweSources.put("CWE-80", Arrays.asList("getParameter", "getHeader", "getCookies"));
        cweSinks.put("CWE-80", Arrays.asList("println", "print", "write"));

        // CWE-113: HTTP Response Splitting
        cweSources.put("CWE-113", Arrays.asList("getParameter", "getHeader"));
        cweSinks.put("CWE-113", Arrays.asList("addHeader", "setHeader", "addCookie"));

        // CWE-134: Format String
        cweSources.put("CWE-134", Arrays.asList("getParameter", "readLine", "nextLine"));
        cweSinks.put("CWE-134", Arrays.asList("printf", "format"));

        // Add more CWEs as needed
    }

    public List<String> getSourcesForCwe(String cweId) {
        return cweSources.getOrDefault(cweId, Collections.emptyList());
    }

    public List<String> getSinksForCwe(String cweId) {
        return cweSinks.getOrDefault(cweId, Collections.emptyList());
    }

    public Map<String, List<String>> getAllSources() {
        return new HashMap<>(cweSources);
    }

    public Map<String, List<String>> getAllSinks() {
        return new HashMap<>(cweSinks);
    }

    /**
     * Determine CWE based on source and sink combination
     */
    public String determineCWE(String source, String sink) {
        // Check each CWE's source/sink combination
        for (Map.Entry<String, List<String>> entry : cweSources.entrySet()) {
            String cweId = entry.getKey();
            List<String> sources = entry.getValue();
            List<String> sinks = cweSinks.get(cweId);

            if (sources != null && sinks != null) {
                boolean sourceMatches = sources.stream().anyMatch(s -> source.contains(s));
                boolean sinkMatches = sinks.contains(sink);

                if (sourceMatches && sinkMatches) {
                    return cweId;
                }
            }
        }

        // Special case for CWE-15 where System.getenv itself is the vulnerability
        if (source.contains("getenv")) {
            return "CWE-15";
        }

        return null;
    }
}