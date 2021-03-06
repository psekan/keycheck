package cz.muni.fi.keycheck;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author David Formanek
 */
public class KeyCheck {

    private static final boolean CHECK_VALIDITY = true;
    private static final boolean CHECK_PRIME_DIFFERENCE = true;
    private static final boolean CHECK_PRIME_UNIQUENESS = true;
    private static final boolean CHECK_PRiVATE_EXPONENT = true;
    private static final boolean CHECK_PRIME_STRENGTH = true;
    private static final boolean CHECK_ORDER_RANDOMNESS = true;
    private static final boolean CHECK_DISTRIBUTION = true;

    private static final boolean GENERATE_AND_TEST = true;
    private static final int GENERATED_PRIME_BITLENGTH = 512;
    private static final long GENERATED_KEY_COUNT = 100000;
    private static final BigInteger EXPONENT_FOR_GENERATED = new BigInteger("65537");

    private static final int PRIME_CERTAINITY = 40;
    private static final int SMOOTH_BOUND = 10000;
    private static final int BITS_FOR_INTERVAL = 5;
    private static final long STATUS_MESSAGE_AFTER = 20000000000L;

    private static long keyCount = 0;
    private static long startTime;
    private static long lastStatusMessageTime;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("specify file name(s)");
            return;
        }
        Stats stats = init();
        if (GENERATE_AND_TEST) {
            testGenerated(GENERATED_KEY_COUNT, GENERATED_PRIME_BITLENGTH, stats);
        } else {
            for (String filename : args) {
                try {
                    load(filename, stats);
                } catch (IOException ex) {
                    System.err.println("IO error: " + ex.getMessage());
                }
            }
        }
        printStats(stats);
    }

    private static void testGenerated(long count, int bits, Stats stats) {
        final SecureRandom rnd = new SecureRandom();
        for (int i = 0; i < count; i++) {
            BigInteger p = new BigInteger(bits, 40, rnd);
            BigInteger q = new BigInteger(bits, 40, rnd);
            BigInteger modulus = p.multiply(q);
            BigInteger phi = modulus.subtract(p).subtract(q).add(BigInteger.ONE);
            if (!phi.gcd(EXPONENT_FOR_GENERATED).equals(BigInteger.ONE)) {
                i--;
                continue;
            }
            Params params = new Params();
            params.setP(p);
            params.setQ(q);
            params.setExponent(EXPONENT_FOR_GENERATED);
            params.setModulus(modulus);
            stats.process(params);
            showProgress();
        }
    }

    private static Stats init() {
        startTime = System.nanoTime();
        StatsContainer stats = new StatsContainer();
        BasicStats basicStats = new BasicStats(
                CHECK_VALIDITY,
                CHECK_PRIME_DIFFERENCE,
                CHECK_PRIME_UNIQUENESS,
                CHECK_PRiVATE_EXPONENT
        );
        stats.add(basicStats);
        if (CHECK_PRIME_STRENGTH) {
            PrimeStrengthStats strengthStats = new PrimeStrengthStats(
                    SMOOTH_BOUND,
                    PRIME_CERTAINITY
            );
            stats.add(strengthStats);
        }
        if (CHECK_ORDER_RANDOMNESS) {
            RandomnessStats randStats = new RandomnessStats();
            stats.add(randStats);
        }
        if (CHECK_DISTRIBUTION) {
            DistributionStats distStats = new DistributionStats(BITS_FOR_INTERVAL);
            stats.add(distStats);
        }
        return stats;
    }

    private static void load(String filename, Stats stats) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            System.out.println("Analysing file '" + filename + "'");
            lastStatusMessageTime = System.nanoTime();
            Params params = null;
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
                        params = readPublicKey(value);
                        break;
                    case "PRIV":
                        if (params == null) {
                            throw new IOException("Loading private key "
                                    + value + "  while public key not loaded");
                        }
                        readPrivateKey(value, params);
                        stats.process(params);
                        params = null;
                        showProgress();
                }
            }
        } catch (FileNotFoundException ex) {
            System.err.println("File '" + filename + "' not found");
        }
    }

    private static Params readPublicKey(String value) throws IOException {
        Params params = new Params();
        BigInteger[] values = parseTlv(value);
        if (values.length != 2) {
            throw new IOException("Public key " + value + " not composed from 2 values");
        }
        params.setExponent(values[0]);
        params.setModulus(values[1]);
        return params;
    }

    private static void readPrivateKey(String value, Params params) throws IOException {
        BigInteger[] values = parseTlv(value);
        if (values.length != 2) {
            throw new IOException("Private key " + value + "  not composed from 2 values");
        }
        params.setP(values[0]);
        params.setQ(values[1]);
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

    private static void showProgress() {
        keyCount++;
        if (keyCount % 100 == 0 && System.nanoTime() - lastStatusMessageTime
                > STATUS_MESSAGE_AFTER) {
            System.out.println(keyCount + " keys processed...");
            lastStatusMessageTime = System.nanoTime();
        }
    }

    private static void printStats(Stats stats) {
        long elapsedTime = (System.nanoTime() - startTime) / 1000000;
        System.out.println("Analysis completed - " + keyCount
                + " keys processed in " + elapsedTime + " ms");
        stats.print();
    }
}
