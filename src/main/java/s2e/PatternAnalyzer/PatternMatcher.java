package s2e.PatternAnalyzer;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.stmt.*;
import com.google.gson.*;
import s2e.ConditionAnalyzer.*;

import java.util.HashSet;
import java.util.Set;


public class PatternMatcher {
    private final ConditionAnalyzer conditionAnalyzer = new ConditionAnalyzer();

    public static Set<String> getUserControlledVars(MethodDeclaration method) {
        Set<String> tainted = new HashSet<>();
        method.findAll(VariableDeclarator.class).forEach(varDecl -> {
            if (varDecl.getInitializer().isPresent()) {
                Expression init = varDecl.getInitializer().get();
                if (isDirectUserInputSource(init)) {
                    tainted.add(varDecl.getNameAsString());
                }
            }
        });
        return tainted;
    }

    private static boolean isDirectUserInputSource(Expression expr) {
        if (expr.isMethodCallExpr()) {
            String callName = expr.asMethodCallExpr().getNameAsString();
            return callName.equals("nextLine") || callName.equals("getParameter") || callName.equals("getenv");
        }
        // Optionally: expand here with more sources as needed.
        return false;
    }


    public boolean matchesPattern(Node node, JsonObject pattern) {
        String nodeType = pattern.get("node_type").getAsString();
        if (!node.getClass().getSimpleName().equals(nodeType)) return false;

        if (node instanceof WhileStmt) {
            WhileStmt ws = (WhileStmt) node;
            if (pattern.has("fields")) {
                JsonObject fields = pattern.getAsJsonObject("fields");
                if (fields.has("potentially_infinite") && fields.get("potentially_infinite").getAsBoolean()) {
                    if (!conditionAnalyzer.isPotentiallyInfiniteCondition(ws.getCondition()))
                        return false;
                }
            }
            if (pattern.has("has_break") && !pattern.get("has_break").getAsBoolean()) {
                boolean hasBreak = ws.getBody().findFirst(BreakStmt.class).isPresent();
                if (hasBreak) return false;
            }
            return true;
        }
        if (node instanceof DoStmt) {
            DoStmt ds = (DoStmt) node;
            if (pattern.has("fields")) {
                JsonObject fields = pattern.getAsJsonObject("fields");
                if (fields.has("potentially_infinite") && fields.get("potentially_infinite").getAsBoolean()) {
                    if (!conditionAnalyzer.isPotentiallyInfiniteCondition(ds.getCondition()))
                        return false;
                }
            }
            if (pattern.has("has_break") && !pattern.get("has_break").getAsBoolean()) {
                boolean hasBreak = ds.getBody().findFirst(BreakStmt.class).isPresent();
                if (hasBreak) return false;
            }
            return true;
        }
        if (node instanceof ForStmt) {
            ForStmt fs = (ForStmt) node;
            boolean potentiallyInfinite = false;
            if (pattern.has("fields")) {
                JsonObject fields = pattern.getAsJsonObject("fields");
                if (fields.has("potentially_infinite") && fields.get("potentially_infinite").getAsBoolean()) {
                    if (!fs.getCompare().isPresent()) {
                        potentiallyInfinite = true;
                    } else {
                        potentiallyInfinite = conditionAnalyzer.isPotentiallyInfiniteCondition(fs.getCompare().get());
                    }
                }
            }
            if (potentiallyInfinite) {
                if (pattern.has("has_break") && !pattern.get("has_break").getAsBoolean()) {
                    boolean hasBreak = fs.getBody().findFirst(BreakStmt.class).isPresent();
                    if (hasBreak) return false;
                }
                return true;
            }
            return false;
        }

        if (node instanceof MethodCallExpr) {
            MethodCallExpr call = (MethodCallExpr) node;
            JsonObject fields = pattern.getAsJsonObject("fields");
            boolean scopeOk = !fields.has("scope") || (call.getScope().isPresent() && call.getScope().get().toString().equals(fields.get("scope").getAsString()));
            boolean methodOk = !fields.has("method_name") || call.getNameAsString().equals(fields.get("method_name").getAsString());

            // Generalized: support argN_user_controlled for any N (e.g., arg2_user_controlled, arg1_user_controlled, etc)
            boolean allArgsOk = true;
            for (String k : fields.keySet()) {
                if (k.matches("arg\\d+_user_controlled") && fields.get(k).getAsBoolean()) {
                    int argIndex = Integer.parseInt(k.replaceAll("\\D", "")) - 1;
                    if (call.getArguments().size() > argIndex) {
                        Expression argExpr = call.getArgument(argIndex);
                        MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
                        boolean argUserControlled = false;
                        if (method != null) {
                            Set<String> taintedVars = getUserControlledVars(method);
                            if (argExpr.isNameExpr()) {
                                argUserControlled = taintedVars.contains(argExpr.asNameExpr().getNameAsString());
                            } else if (isDirectUserInputSource(argExpr)) {
                                argUserControlled = true;
                            }
                        }
                        allArgsOk = allArgsOk && argUserControlled;
                    } else {
                        allArgsOk = false;
                    }
                }
            }

            // Fallback: original logic for arg_user_controlled (any arg)
            boolean argUserControlled = false;
            if (fields.has("arg_user_controlled") && fields.get("arg_user_controlled").getAsBoolean()) {
                for (Expression arg : call.getArguments()) {
                    if (isDirectUserInputSource(arg)) {
                        argUserControlled = true;
                        break;
                    }
                }
            } else {
                argUserControlled = true;
            }

            // Both allArgsOk and argUserControlled must be true (for safety)
            return scopeOk && methodOk && allArgsOk && argUserControlled;
        }


        return false;
    }

    private static boolean isUserControlled(Expression expr) {
        // Checks for classic sources of user input
        if (expr.isMethodCallExpr()) {
            String callName = expr.asMethodCallExpr().getNameAsString();
            // Scanner.nextLine(), request.getParameter(), System.getenv()
            if (callName.equals("nextLine") || callName.equals("getParameter") || callName.equals("getenv")) {
                return true;
            }
        }
        if (expr.isNameExpr()) {
            // You could track variable assignments for flow-sensitivity (not implemented here)
            // For now, just flag if var name is "data", "input", etc.
            String name = expr.asNameExpr().getNameAsString().toLowerCase();
            return name.contains("data") || name.contains("input") || name.contains("param");
        }
        // Expand with more logic as needed (assignment tracking)
        return false;
    }


}
