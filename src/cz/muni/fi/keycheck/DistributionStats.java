package cz.muni.fi.keycheck;

import java.math.BigInteger;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @author David Formanek
 */
class DistributionStats implements Stats {

    private int bitsForInterval = 4;
    
    private long keyCount = 0;
    private Map<Integer, Long> intervalCounts = new HashMap<>();

    public DistributionStats(int bitsForInterval) {
        this.bitsForInterval = bitsForInterval;
    }

    @Override
    public void process(Params params) {
        incrementMap(intervalCounts, topBits(params.getP(), bitsForInterval));
        incrementMap(intervalCounts, topBits(params.getQ(), bitsForInterval));
        keyCount++;
    }

    private int topBits(BigInteger n, int bits) {
        return n.shiftRight(n.bitLength() - bits).intValueExact();
    }
    
    @Override
    public void print() {
        System.out.println("Distribution of top " + bitsForInterval + " bits of primes");
        printMapChart(intervalCounts, keyCount * 2, 300);
    }

    private long incrementMap(Map<Integer, Long> map, int value) {
        long count = map.getOrDefault(value, Long.valueOf(0));
        count++;
        map.put(value, count);
        return count;
    }
    
    private void printMapChart(Map<Integer, Long> map, long size, int symbols) {
        int maxKey = Collections.max(map.keySet());
        for (int i = (maxKey + 1) / 2; i <= maxKey; i++) {
            System.out.print(Integer.toBinaryString(i) + ": ");
            long value = map.getOrDefault(i, Long.valueOf(0));
            int width = (int) (value * symbols / size);
            if (width == 0 && value != 0) {
                System.out.print(".");
            }
            for (int j = 0; j < width; j++) {
                System.out.print("*");
            }
            double percentage = 100 * value / (double) size;
            System.out.format(" %d (%.4f %%)\n", value, percentage);
        }
    }
}
