package cz.muni.fi.keycheck;

import java.math.BigInteger;

/**
 *
 * @author David Formanek
 */
public class RandomnessStats implements Stats {

    private long keyCount = 0;
    private BigInteger prevP;
    private BigInteger prevQ;
    private BigInteger prevPrevP;
    private BigInteger prevPrevQ;
    private long turningPointCount = 0;
    private long turningPointCountP = 0;
    private long turningPointCountQ = 0;
    private long positiveDifferenceCount = 0;
    private long positiveDifferenceCountP = 0;
    private long positiveDifferenceCountQ = 0;
    private long primeDifferenceSignumSum = 0;

    public BigInteger getPrevP() {
        return prevP;
    }

    public void setPrevP(BigInteger prevP) {
        this.prevP = prevP;
    }

    public BigInteger getPrevQ() {
        return prevQ;
    }

    public void setPrevQ(BigInteger prevQ) {
        this.prevQ = prevQ;
    }

    public BigInteger getPrevPrevP() {
        return prevPrevP;
    }

    public void setPrevPrevP(BigInteger prevPrevP) {
        this.prevPrevP = prevPrevP;
    }

    public BigInteger getPrevPrevQ() {
        return prevPrevQ;
    }

    public void setPrevPrevQ(BigInteger prevPrevQ) {
        this.prevPrevQ = prevPrevQ;
    }

    @Override
    public void process(Params params) {
        checkTurningPoints(params);
        checkTrend(params);
        prevPrevP = prevP;
        prevP = params.getP();
        prevPrevQ = prevQ;
        prevQ = params.getQ();
        keyCount++;
    }

    private void checkTurningPoints(Params params) {
        turningPointCount += getTurningPoint(prevP, prevQ, params.getP());
        turningPointCount += getTurningPoint(prevQ, params.getP(), params.getQ());
        turningPointCountP += getTurningPoint(prevPrevP, prevP, params.getP());
        turningPointCountQ += getTurningPoint(prevPrevQ, prevQ, params.getQ());
    }

    private int getTurningPoint(BigInteger a, BigInteger b, BigInteger c) {
        if (a == null) {
            return 0;
        }
        int abComparison = a.compareTo(b);
        int bcComparison = b.compareTo(c);
        return abComparison * bcComparison < 0 ? 1 : 0;
    }

    private double standardizedTurningPoints(long y, long n) {
        double numerator = y - 2 * (n - 2) / 3.0;
        double denominator = Math.sqrt((16 * n - 29) / 90.0);
        return numerator / denominator;
    }

    private void checkTrend(Params params) {
        positiveDifferenceCount += getPositiveDifference(prevQ, params.getP());
        positiveDifferenceCount += getPositiveDifference(params.getP(), params.getQ());
        primeDifferenceSignumSum += params.getP().compareTo(params.getQ());
        positiveDifferenceCountP += getPositiveDifference(prevP, params.getP());
        positiveDifferenceCountQ += getPositiveDifference(prevQ, params.getQ());
    }

    private int getPositiveDifference(BigInteger a, BigInteger b) {
        if (a != null && a.compareTo(b) < 0) {
            return 1;
        }
        return 0;
    }

    private double standardizedPositiveDifference(long y, long n) {
        double numerator = y - (n - 1) / 2.0;
        double denominator = Math.sqrt((n + 1) / 12.0);
        return numerator / denominator;
    }

    @Override
    public void print() {
        System.out.println("There are " + turningPointCountP + " and " + turningPointCountQ
                + " turning points in the prime sequence for p and q, standardized statistics is "
                + standardizedTurningPoints(turningPointCountP, keyCount) + " and "
                + standardizedTurningPoints(turningPointCountQ, keyCount)
        );
        System.out.println("There are " + positiveDifferenceCountP + " and " + positiveDifferenceCountQ
                + " positive differences in the prime sequence for p and q, standardized statistics is "
                + standardizedPositiveDifference(positiveDifferenceCountP, keyCount) + " and "
                + standardizedPositiveDifference(positiveDifferenceCountQ, keyCount)
        );
        if (primeDifferenceSignumSum == keyCount || -primeDifferenceSignumSum == keyCount) {
            System.out.println("Primes p and q are ordered, overall statistics not determined");
        } else {
            System.out.println("Primes p and q are not ordered (sum of signums of differences is "
                    + primeDifferenceSignumSum + "), there are overall "
                    + turningPointCount + " turning points, standardized "
                    + standardizedTurningPoints(turningPointCount, 2 * keyCount)
                    + ", and " + positiveDifferenceCount + " positive differences, standardized "
                    + standardizedPositiveDifference(positiveDifferenceCount, 2 * keyCount)
            );
        }
    }
}
