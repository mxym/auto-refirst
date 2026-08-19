import java.util.function.IntUnaryOperator;
public class LambdaSample {
    private final String prefix = "FLAG";
    public int check(int x) {
        IntUnaryOperator op = y -> (y * 7) ^ 0x55;
        return op.applyAsInt(x);
    }
    public String format(int x) { return prefix + ":" + x; }
}
