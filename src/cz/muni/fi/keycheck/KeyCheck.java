package cz.muni.fi.keycheck;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author David Formanek
 */
public class KeyCheck {
    
    private static final boolean CHECK_PRIME_STRENGTH = false;
    private static final boolean CHECK_ORDER_RANDOMNESS = true;
    
    private static final int RADIX = 10;
    private static final int PRIME_CERTAINITY = 40;
    private static final int SMOOTH_BOUND = 10000;
    private static final long STATUS_MESSAGE_AFTER = 20000000000L;

    //private static boolean publicKeyLoaded = false;
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
        BasicStats stats = new BasicStats();
        PrimeStrengthStats strengthStats = new PrimeStrengthStats(SMOOTH_BOUND, PRIME_CERTAINITY);
        RandomnessStats randStats = new RandomnessStats();
        try {
            startTime = System.nanoTime();
            for (String filename : args) {
                load(filename, stats, strengthStats, randStats);
            }
            printStats(stats, strengthStats, randStats);
        } catch (IOException ex) {
            System.err.println("IO error: " + ex.getMessage());
        }
    }
    
    private static void load(String filename, BasicStats stats,
            PrimeStrengthStats strengthStats, RandomnessStats randStats) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            System.out.println("Analysing file '" + filename + "'");
            lastStatusMessageTime = System.nanoTime();
            boolean publicKeyLoaded = false;
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
                        params = new Params();
                        readPublicKey(value, params);
                        publicKeyLoaded = true;
                        break;
                    case "PRIV":
                        if (!publicKeyLoaded) {
                            throw new IOException("Loading private key "
                                    + value + "  while public key not loaded");
                        }
                        readPrivateKey(value, params);
                        stats.process(params);
                        if (CHECK_PRIME_STRENGTH) {
                            strengthStats.process(params);
                        }
                        if (CHECK_ORDER_RANDOMNESS) {
                            randStats.process(params);
                        }
                        keyCount++;
                        publicKeyLoaded = false;
                        if (keyCount % 100 == 0 && System.nanoTime() - lastStatusMessageTime
                                > STATUS_MESSAGE_AFTER) {
                            System.out.println(keyCount + " keys processed...");
                            lastStatusMessageTime = System.nanoTime();
                        }
                }
            }
        } catch (FileNotFoundException ex) {
            System.err.println("File '" + filename + "' not found");
        }
    }
    
    private static void readPublicKey(String value, Params params) throws IOException {
        BigInteger[] values = parseTlv(value);
        if (values.length != 2) {
            throw new IOException("Public key " + value + " not composed from 2 values");
        }
        params.setExponent(values[0]);
        params.setModulus(values[1]);
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
    
    private static void printStats(BasicStats stats, PrimeStrengthStats strengthStats, RandomnessStats randStats) {
        System.out.println();
        long elapsedTime = (System.nanoTime() - startTime) / 1000000;
        System.out.println("Analysis completed - " + keyCount
                + " keys processed in " + elapsedTime + " ms");
        stats.print(keyCount, RADIX);
        if (CHECK_PRIME_STRENGTH) {
            strengthStats.print(keyCount);
        }
        if (CHECK_ORDER_RANDOMNESS) {
            randStats.print(keyCount);
        }
    }
}
