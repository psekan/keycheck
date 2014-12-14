package cz.muni.fi.keycheck;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 *
 * @author David Formanek
 */
public class KeyCheck {

    private static final boolean CHECK_VALIDITY = false;
    private static final boolean CHECK_PRIME_DIFFERENCE = false;
    private static final boolean CHECK_PRIME_UNIQUENESS = false;
    private static final boolean CHECK_PRiVATE_EXPONENT = false;
    private static final boolean CHECK_PRIME_STRENGTH = false;
    private static final boolean CHECK_ORDER_RANDOMNESS = true;

    private static final int RADIX = 10;
    private static final int PRIME_CERTAINITY = 40;
    private static final int SMOOTH_BOUND = 10000;
    private static final long STATUS_MESSAGE_AFTER = 20000000000L;

    private static BigInteger exponent;
    private static BigInteger modulus;
    private static BigInteger primeP;
    private static BigInteger primeQ;
    private static BigInteger prevPrimeP;
    private static BigInteger prevPrimeQ;
    private static BigInteger prevPrevPrimeP;
    private static BigInteger prevPrevPrimeQ;
    private static boolean publicKeyLoaded = false;

    private static long startTime;
    private static long lastStatusMessageTime;
    private static long keyCount = 0;
    private static long validKeyCount = 0;
    private static long duplicitKeyCount = 0;
    private static BigInteger minPrimeDifference = null;
    private static Set<BigInteger> primes = new HashSet<>();
    private static BigInteger minPrivateExponent = null;

    private static List<BigInteger> primesUnderBound = getPrimesUnder(SMOOTH_BOUND);
    private static long smoothNumberCount = 0;
    private static long factoredNumberCount = 0;
    private static Map<Integer, Long> smallFactorCounts = new HashMap<>();
    private static Map<Integer, Long> smoothPartLengths = new HashMap<>();

    private static long turningPointCount = 0;
    private static long turningPointCountP = 0;
    private static long turningPointCountQ = 0;
    private static long positiveDifferenceCount = 0;
    private static long positiveDifferenceCountP = 0;
    private static long positiveDifferenceCountQ = 0;
    private static long primeDifferenceSignumSum = 0;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("specify file name(s)");
            return;
        }
        try {
            startTime = System.nanoTime();
            for (String filename : args) {
                load(filename);
            }
            printStats();
        } catch (IOException ex) {
            System.err.println("IO error: " + ex.getMessage());
        }
    }

    private static void load(String filename) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            System.out.println("Analysing file '" + filename + "'");
            lastStatusMessageTime = System.nanoTime();
            for (;;) {
                String line = reader.readLine();
                if (line == null) {
                    break;
                }
                String[] tuple = line.split(":", 2);
                if (tuple.length != 2) {
                    continue;
                }
                String value = tuple[1].replaceAll("\\s", "");
                switch (tuple[0]) {
                    case "PUBL":
                        readPublicKey(value);
                        break;
                    case "PRIV":
                        readPrivateKey(value);
                        break;
                }
            }
        } catch (FileNotFoundException ex) {
            System.err.println("File '" + filename + "' not found");
        }
    }

    private static void readPublicKey(String value) throws IOException {
        BigInteger[] values = parseTlv(value);
        if (values.length != 2) {
            throw new IOException("Public key " + value + " not composed from 2 values");
        }
        exponent = values[0];
        modulus = values[1];
        publicKeyLoaded = true;
    }

    private static void readPrivateKey(String value) throws IOException {
        if (!publicKeyLoaded) {
            throw new IOException("Loading private key " + value + "  while public key not loaded");
        }
        BigInteger[] values = parseTlv(value);
        if (values.length != 2) {
            throw new IOException("Private key " + value + "  not composed from 2 values");
        }
        prevPrevPrimeP = prevPrimeP;
        prevPrimeP = primeP;
        primeP = values[0];
        prevPrevPrimeQ = prevPrimeQ;
        prevPrimeQ = primeQ;
        primeQ = values[1];
        process();
    }

    private static BigInteger[] parseTlv(String values) throws IOException {
        int totalLength = values.length();
        if (totalLength % 2 == 1) {
            throw new IOException("Odd String length of " + values);
        }
        List<BigInteger> result = new ArrayList<>();
        int length;
        for (int offset = 0; offset != totalLength; offset += 6 + 2 * length) {
            if (offset > totalLength) {
                throw new IOException("Invalid TLV length in " + values);
            }
            if (!values.startsWith("82", offset)) {
                throw new IOException("Invalid TLV type in " + values);
            }
            length = Integer.parseInt(values.substring(offset + 2, offset + 6), 16);
            String value = values.substring(offset + 6, offset + 6 + 2 * length);
            result.add(new BigInteger(value, 16));
        }
        return result.toArray(new BigInteger[result.size()]);
    }

    private static void process() {
        if (CHECK_VALIDITY) {
            checkValidity();
        }
        if (CHECK_PRIME_DIFFERENCE) {
            checkPrimeDifference();
        }
        if (CHECK_PRIME_UNIQUENESS) {
            checkPrimeUniqueness();
        }
        if (CHECK_PRiVATE_EXPONENT) {
            checkPrivateExponent();
        }
        if (CHECK_PRIME_STRENGTH) {
            checkPrimeStrength();
        }
        if (CHECK_ORDER_RANDOMNESS) {
            checkTurningPoints();
            checkTrend();
        }
        keyCount++;
        publicKeyLoaded = false;
        if (keyCount % 100 == 0 && System.nanoTime() - lastStatusMessageTime > STATUS_MESSAGE_AFTER) {
            System.out.println(keyCount + " keys processed...");
            lastStatusMessageTime = System.nanoTime();
        }
    }

    private static void checkValidity() {
        boolean isValid = true;
        if (!primeP.isProbablePrime(PRIME_CERTAINITY)) {
            isValid = false;
            System.out.println(primeP.toString(RADIX) + " is not a prime");
        }
        if (!primeQ.isProbablePrime(PRIME_CERTAINITY)) {
            isValid = false;
            System.out.println(primeP.toString(RADIX) + " is not a prime");
        }
        if (!primeP.multiply(primeQ).equals(modulus)) {
            isValid = false;
            System.out.println("Modulus " + modulus.toString(RADIX) + " has not factors p a q");
        }
        BigInteger phi = modulus.subtract(primeP).subtract(primeQ).add(BigInteger.ONE);
        if (!phi.gcd(exponent).equals(BigInteger.ONE)) {
            isValid = false;
            System.out.println("Exponent " + exponent.toString(RADIX)
                    + " is not coprime to phi of " + modulus.toString(RADIX));
        }
        if (isValid) {
            validKeyCount++;
        }
    }

    private static void checkPrimeDifference() {
        BigInteger difference = primeP.subtract(primeQ).abs();
        if (minPrimeDifference == null || minPrimeDifference.compareTo(difference) > 0) {
            minPrimeDifference = difference;
        }
    }

    private static void checkPrimeUniqueness() {
        if (!primes.add(primeP)) {
            duplicitKeyCount++;
            System.out.println("Prime " + primeP + " is duplicit!");
        }
        if (!primes.add(primeQ)) {
            duplicitKeyCount++;
            System.out.println("Prime " + primeQ + " is duplicit!");
        }
    }

    private static void checkPrivateExponent() {
        BigInteger phi = modulus.subtract(primeP).subtract(primeQ).add(BigInteger.ONE);
        BigInteger privateExponent = exponent.modInverse(phi);
        if (minPrivateExponent == null || minPrivateExponent.compareTo(privateExponent) > 0) {
            minPrivateExponent = privateExponent;
        }
    }

    private static void checkPrimeStrength() {
        BigInteger primeMinusOne = primeP.subtract(BigInteger.ONE);
        checkSmoothness(primeMinusOne);
        primeMinusOne = primeQ.subtract(BigInteger.ONE);
        checkSmoothness(primeMinusOne);
    }

    private static void checkSmoothness(BigInteger n) {
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
        if (n.isProbablePrime(PRIME_CERTAINITY)) {
            factoredNumberCount++;
        }
    }

    private static long incrementMap(Map<Integer, Long> map, int value) {
        long count = map.getOrDefault(value, Long.valueOf(0));
        count++;
        map.put(value, count);
        return count;
    }

    private static List<BigInteger> getPrimesUnder(int bound) {
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

    private static void checkTurningPoints() {
        if (prevPrimeP == null) {
            return;
        }
        if (prevPrimeQ.compareTo(prevPrimeP) < 0 && prevPrimeQ.compareTo(primeP) < 0) {
            turningPointCount++;
        } else if (prevPrimeQ.compareTo(prevPrimeP) > 0 && prevPrimeQ.compareTo(primeP) > 0) {
            turningPointCount++;
        }
        if (primeP.compareTo(prevPrimeQ) < 0 && primeP.compareTo(primeQ) < 0) {
            turningPointCount++;
        } else if (primeP.compareTo(prevPrimeQ) > 0 && primeP.compareTo(primeQ) > 0) {
            turningPointCount++;
        }
        // check for primes p and q separately
        if (prevPrevPrimeP == null) {
            return;
        }
        if (prevPrimeP.compareTo(prevPrevPrimeP) < 0 && prevPrimeP.compareTo(primeP) < 0) {
            turningPointCountP++;
        } else if (prevPrimeP.compareTo(prevPrevPrimeP) > 0 && prevPrimeP.compareTo(primeP) > 0) {
            turningPointCountP++;
        }
        if (prevPrimeQ.compareTo(prevPrevPrimeQ) < 0 && prevPrimeQ.compareTo(primeQ) < 0) {
            turningPointCountQ++;
        } else if (prevPrimeQ.compareTo(prevPrevPrimeQ) > 0 && prevPrimeQ.compareTo(primeQ) > 0) {
            turningPointCountQ++;
        }
    }

    private static double standardizedTurningPoints(long y, long n) {
        double numerator = y - 2 * (n - 2) / 3.0;
        double denominator = Math.sqrt((16 * n - 29) / 90.0);
        return numerator / denominator;
    }

    private static void checkTrend() {
        if (prevPrimeQ != null && prevPrimeQ.compareTo(primeP) < 0) {
            positiveDifferenceCount++;
        }
        if (primeP.compareTo(primeQ) < 0) {
            positiveDifferenceCount++;
        }
        primeDifferenceSignumSum += primeP.compareTo(primeQ);
        if (prevPrimeP != null && prevPrimeP.compareTo(primeP) < 0) {
            positiveDifferenceCountP++;
        }
        if (prevPrimeQ != null && prevPrimeQ.compareTo(primeQ) < 0) {
            positiveDifferenceCountQ++;
        }
    }

    private static double standardizedPositiveDifference(long y, long n) {
        double numerator = y - (n - 1) / 2.0;
        double denominator = Math.sqrt((n + 1) / 12.0);
        return numerator / denominator;
    }

    private static void printStats() {
        System.out.println();
        long elapsedTime = (System.nanoTime() - startTime) / 1000000;
        System.out.println("Analysis completed - " + keyCount
                + " keys processed in " + elapsedTime + " ms");
        if (CHECK_VALIDITY) {
            System.out.println(validKeyCount + " keys are valid, "
                    + (keyCount - validKeyCount) + " invalid");
        }
        if (CHECK_PRIME_UNIQUENESS) {
            if (duplicitKeyCount == 0) {
                System.out.println("All primes are unique");
            } else {
                System.out.println(duplicitKeyCount + " primes are not unique");
            }
        }
        if (CHECK_PRiVATE_EXPONENT && minPrivateExponent != null) {
            System.out.println("Minimum private exponent: " + minPrivateExponent.toString(RADIX)
                    + " (bitlength " + minPrivateExponent.bitLength() + ")");
        }
        if (CHECK_PRIME_DIFFERENCE && minPrimeDifference != null) {
            System.out.println("Minimum prime difference: " + minPrimeDifference.toString(RADIX)
                    + " (bitlength " + minPrimeDifference.bitLength() + ")");
        }
        if (CHECK_PRIME_STRENGTH) {
            System.out.println("Frequency distribution for count of (p-1) factors less than " + SMOOTH_BOUND);
            printMapChart(smallFactorCounts, keyCount * 2, 300);
            System.out.println("Frequency distribution for bitlength of product"
                    + " of all (p-1) factors less than " + SMOOTH_BOUND);
            printMapChart(smoothPartLengths, keyCount * 2, 300);
            System.out.println(smoothNumberCount + " (p-1) numbers are " + SMOOTH_BOUND + "-smooth, "
                    + factoredNumberCount + " have only one bigger factor");
        }
        if (CHECK_ORDER_RANDOMNESS) {
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

    private static void printMapChart(Map<Integer, Long> map, long size, int symbols) {
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
