package s2e.ConditionAnalyzer;
import com.github.javaparser.ast.expr.*;


public class ConditionAnalyzer {
    // Try to decide if an expression is "potentially always true"
    public boolean isPotentiallyInfiniteCondition(Expression expr) {
        expr = unwrapExpr(expr);
        if (expr == null) return false;

        if (expr.isBooleanLiteralExpr() && expr.asBooleanLiteralExpr().getValue())
            return true;

        if (expr.isBinaryExpr()) {
            BinaryExpr be = expr.asBinaryExpr();
            BinaryExpr.Operator op = be.getOperator();
            if (be.getLeft().isLiteralExpr() && be.getRight().isLiteralExpr()) {
                try {
                    int left = Integer.parseInt(be.getLeft().toString());
                    int right = Integer.parseInt(be.getRight().toString());
                    switch (op) {
                        case EQUALS: return left == right;
                        case GREATER: return left > right;
                        case GREATER_EQUALS: return left >= right;
                        case LESS: return left < right;
                        case LESS_EQUALS: return left <= right;
                    }
                } catch (Exception ignore) {}
            }
            if (be.getLeft().isNameExpr() && be.getRight().isIntegerLiteralExpr()) {
                int right = Integer.parseInt(be.getRight().asIntegerLiteralExpr().getValue());
                switch (op) {
                    case GREATER_EQUALS: return right == 0;
                    case LESS: return false;
                    default: return false;
                }
            }
        }
        return false;
    }

    // Remove parentheses, etc.
    private Expression unwrapExpr(Expression expr) {
        while (expr != null && expr.isEnclosedExpr()) {
            expr = expr.asEnclosedExpr().getInner();
        }
        return expr;
    }
}