package cz.muni.fi.keycheck;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 *
 * @author David Formanek
 */
public class PrimeStrengthStats {

    private int smoothBound;
    private List<BigInteger> primesUnderBound;
    private int primeCertainity;
    private long smoothNumberCount = 0;
    private long factoredNumberCount = 0;
    private Map<Integer, Long> smallFactorCounts = new HashMap<>();
    private Map<Integer, Long> smoothPartLengths = new HashMap<>();

    public PrimeStrengthStats(int smoothBound, int primeCertainity) {
        this.smoothBound = smoothBound;
        primesUnderBound = getPrimesUnder(smoothBound);
        this.primeCertainity = primeCertainity;
    }

    void process(Params params) {
        checkSmoothness(params.getP().subtract(BigInteger.ONE));
        checkSmoothness(params.getQ().subtract(BigInteger.ONE));
    }

    private void checkSmoothness(BigInteger n) {
        int nSmallFactors = 0;
        BigInteger smoothPart = BigInteger.ONE;
        for (BigInteger prime : primesUnderBound) {
            for (;;) {
                if (n.mod(prime).equals(BigInteger.ZERO)) {
                    n = n.divide(prime);
                    nSmallFactors++;
                    smoothPart = smoothPart.multiply(prime);
                } else {
                    break;
                }
            }
        }
        incrementMap(smallFactorCounts, nSmallFactors);
        incrementMap(smoothPartLengths, smoothPart.bitLength());

        if (n.equals(BigInteger.ONE)) {
            smoothNumberCount++;
        }
        if (n.isProbablePrime(primeCertainity)) {
            factoredNumberCount++;
        }
    }

    private long incrementMap(Map<Integer, Long> map, int value) {
        long count = map.getOrDefault(value, Long.valueOf(0));
        count++;
        map.put(value, count);
        return count;
    }

    private List<BigInteger> getPrimesUnder(int bound) {
        // Sieve of Eratosthenes
        final int sqrt = (int) Math.sqrt(bound) + 1;
        boolean[] isComposite = new boolean[bound];
        for (int i = 2; i < sqrt; i++) {
            if (!isComposite[i]) {
                for (int j = i * i; j < bound; j += i) {
                    isComposite[j] = true;
                }
            }
        }
        List<BigInteger> smallPrimes = new ArrayList<>();
        for (int i = 2; i < bound; i++) {
            if (!isComposite[i]) {
                smallPrimes.add(BigInteger.valueOf(i));
            }
        }
        return smallPrimes;
    }

    void print(long keyCount) {
        System.out.println("Frequency distribution for count of (p-1) factors less than " + smoothBound);
        printMapChart(smallFactorCounts, keyCount * 2, 300);
        System.out.println("Frequency distribution for bitlength of product"
                + " of all (p-1) factors less than " + smoothBound);
        printMapChart(smoothPartLengths, keyCount * 2, 300);
        System.out.println(smoothNumberCount + " (p-1) numbers are " + smoothBound + "-smooth, "
                + factoredNumberCount + " have only one bigger factor");
    }

    private void printMapChart(Map<Integer, Long> map, long size, int symbols) {
        int maxKey = Collections.max(map.keySet());
        for (int i = 0; i <= maxKey; i++) {
            System.out.format("%3d: ", i);
            long value = map.getOrDefault(i, Long.valueOf(0));
            int width = (int) (value * symbols / size);
            if (width == 0 && value != 0) {
                System.out.print(".");
            }
            for (int j = 0; j < width; j++) {
                System.out.print("*");
            }
            double percentage = 100 * value / (double) size;
            System.out.format(" %d (%.3f %%)\n", value, percentage);
        }
    }
}
