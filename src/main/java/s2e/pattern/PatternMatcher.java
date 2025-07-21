package s2e.pattern;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.stmt.*;
import com.google.gson.*;
import s2e.condition.ConditionAnalyzer;

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

        method.findAll(com.github.javaparser.ast.expr.AssignExpr.class).forEach(assign -> {
            if (assign.getTarget().isNameExpr() && isDirectUserInputSource(assign.getValue())) {
                tainted.add(assign.getTarget().asNameExpr().getNameAsString());
            }
        });

        method.findAll(MethodCallExpr.class).forEach(call -> {
            if (isDirectUserInputSource(call)) {
                Node parent = call.getParentNode().orElse(null);
                if (parent instanceof VariableDeclarator) {
                    tainted.add(((VariableDeclarator) parent).getNameAsString());
                } else if (parent instanceof com.github.javaparser.ast.expr.AssignExpr) {
                    com.github.javaparser.ast.expr.AssignExpr assign = (com.github.javaparser.ast.expr.AssignExpr) parent;
                    if (assign.getTarget().isNameExpr()) {
                        tainted.add(assign.getTarget().asNameExpr().getNameAsString());
                    }
                }
            }
        });

        return tainted;
    }

    private static boolean isDirectUserInputSource(Expression expr) {
        if (expr.isMethodCallExpr()) {
            MethodCallExpr call = expr.asMethodCallExpr();
            String callName = call.getNameAsString();

            if (callName.equals("nextLine") || callName.equals("next") ||
                    callName.equals("getParameter") || callName.equals("getHeader") ||
                    callName.equals("getenv") || callName.equals("readLine") ||
                    callName.equals("getInputStream") || callName.equals("getCookies")) {
                return true;
            }

            if (callName.equals("getenv") && call.getScope().isPresent() &&
                    call.getScope().get().toString().equals("System")) {
                return true;
            }
        }
        return false;
    }

    public boolean matchesPattern(Node node, JsonObject pattern) {
        String nodeType = pattern.get("node_type").getAsString();
        if (!node.getClass().getSimpleName().equals(nodeType)) return false;

        if (node instanceof WhileStmt) {
            return matchesWhilePattern((WhileStmt) node, pattern);
        }
        if (node instanceof DoStmt) {
            return matchesDoPattern((DoStmt) node, pattern);
        }
        if (node instanceof ForStmt) {
            return matchesForPattern((ForStmt) node, pattern);
        }
        if (node instanceof MethodCallExpr) {
            return matchesMethodCallPattern((MethodCallExpr) node, pattern);
        }

        return false;
    }

    private boolean matchesWhilePattern(WhileStmt ws, JsonObject pattern) {
        if (pattern.has("fields")) {
            JsonObject fields = pattern.getAsJsonObject("fields");

            if (fields.has("potentially_infinite") && fields.get("potentially_infinite").getAsBoolean()) {
                if (!conditionAnalyzer.isPotentiallyInfiniteCondition(ws.getCondition()))
                    return false;
            }

            if (fields.has("condition_user_controlled") && fields.get("condition_user_controlled").getAsBoolean()) {
                if (!isExpressionUserControlled(ws.getCondition(), ws))
                    return false;
            }
        }

        if (pattern.has("has_break") && !pattern.get("has_break").getAsBoolean()) {
            boolean hasBreak = ws.getBody().findFirst(BreakStmt.class).isPresent();
            if (hasBreak) return false;
        }

        return true;
    }

    private boolean matchesDoPattern(DoStmt ds, JsonObject pattern) {
        if (pattern.has("fields")) {
            JsonObject fields = pattern.getAsJsonObject("fields");

            if (fields.has("potentially_infinite") && fields.get("potentially_infinite").getAsBoolean()) {
                if (!conditionAnalyzer.isPotentiallyInfiniteCondition(ds.getCondition()))
                    return false;
            }

            if (fields.has("condition_user_controlled") && fields.get("condition_user_controlled").getAsBoolean()) {
                if (!isExpressionUserControlled(ds.getCondition(), ds))
                    return false;
            }
        }

        if (pattern.has("has_break") && !pattern.get("has_break").getAsBoolean()) {
            boolean hasBreak = ds.getBody().findFirst(BreakStmt.class).isPresent();
            if (hasBreak) return false;
        }

        return true;
    }

    private boolean matchesForPattern(ForStmt fs, JsonObject pattern) {
        if (pattern.has("fields")) {
            JsonObject fields = pattern.getAsJsonObject("fields");

            if (fields.has("potentially_infinite") && fields.get("potentially_infinite").getAsBoolean()) {
                boolean potentiallyInfinite = false;
                if (!fs.getCompare().isPresent()) {
                    potentiallyInfinite = true;
                } else {
                    potentiallyInfinite = conditionAnalyzer.isPotentiallyInfiniteCondition(fs.getCompare().get());
                }
                if (!potentiallyInfinite) return false;
            }

            if (fields.has("condition_user_controlled") && fields.get("condition_user_controlled").getAsBoolean()) {
                if (fs.getCompare().isPresent() && !isExpressionUserControlled(fs.getCompare().get(), fs))
                    return false;
            }
        }

        if (pattern.has("has_break") && !pattern.get("has_break").getAsBoolean()) {
            boolean hasBreak = fs.getBody().findFirst(BreakStmt.class).isPresent();
            if (hasBreak) return false;
        }

        return true;
    }

    private boolean matchesMethodCallPattern(MethodCallExpr call, JsonObject pattern) {
        JsonObject fields = pattern.getAsJsonObject("fields");

        boolean scopeOk = true;
        if (fields.has("scope")) {
            scopeOk = call.getScope().isPresent() &&
                    call.getScope().get().toString().equals(fields.get("scope").getAsString());
        }
        if (fields.has("scope_contains")) {
            scopeOk = call.getScope().isPresent() &&
                    call.getScope().get().toString().contains(fields.get("scope_contains").getAsString());
        }
        if (fields.has("scope_type")) {
            scopeOk = call.getScope().isPresent() &&
                    call.getScope().get().toString().contains(fields.get("scope_type").getAsString());
        }

        boolean methodOk = !fields.has("method_name") ||
                call.getNameAsString().equals(fields.get("method_name").getAsString());

        boolean allArgsOk = true;
        for (String k : fields.keySet()) {
            if (k.matches("arg\\d+_user_controlled") && fields.get(k).getAsBoolean()) {
                int argIndex = Integer.parseInt(k.replaceAll("\\D", "")) - 1;
                if (call.getArguments().size() > argIndex) {
                    Expression argExpr = call.getArgument(argIndex);
                    if (!isArgumentUserControlled(argExpr, call)) {
                        allArgsOk = false;
                    }
                } else {
                    allArgsOk = false;
                }
            }
        }

        boolean argUserControlled = true;
        if (fields.has("arg_user_controlled") && fields.get("arg_user_controlled").getAsBoolean()) {
            argUserControlled = false;
            for (Expression arg : call.getArguments()) {
                if (isArgumentUserControlled(arg, call)) {
                    argUserControlled = true;
                    break;
                }
            }
        }

        boolean argConcatenation = true;
        if (fields.has("arg_contains_concatenation") && fields.get("arg_contains_concatenation").getAsBoolean()) {
            argConcatenation = false;
            for (Expression arg : call.getArguments()) {
                if (arg.toString().contains("+")) {
                    argConcatenation = true;
                    break;
                }
            }
        }

        return scopeOk && methodOk && allArgsOk && argUserControlled && argConcatenation;
    }

    private boolean isExpressionUserControlled(Expression expr, Node context) {
        if (isDirectUserInputSource(expr)) {
            return true;
        }

        MethodDeclaration method = context.findAncestor(MethodDeclaration.class).orElse(null);
        if (method != null) {
            Set<String> taintedVars = getUserControlledVars(method);
            Set<String> referencedVars = new HashSet<>();
            expr.findAll(NameExpr.class).forEach(ne -> referencedVars.add(ne.getNameAsString()));

            for (String var : referencedVars) {
                if (taintedVars.contains(var)) {
                    return true;
                }
            }
        }

        String exprStr = expr.toString().toLowerCase();
        return exprStr.contains("data") || exprStr.contains("input") ||
                exprStr.contains("param") || exprStr.contains("user");
    }

    private boolean isArgumentUserControlled(Expression arg, MethodCallExpr call) {
        if (isDirectUserInputSource(arg)) {
            return true;
        }

        MethodDeclaration method = call.findAncestor(MethodDeclaration.class).orElse(null);
        if (method != null && arg.isNameExpr()) {
            Set<String> taintedVars = getUserControlledVars(method);
            return taintedVars.contains(arg.asNameExpr().getNameAsString());
        }

        return isExpressionUserControlled(arg, call);
    }
}