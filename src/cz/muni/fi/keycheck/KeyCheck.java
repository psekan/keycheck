package cz.muni.fi.keycheck;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 * @author David Formanek
 */
public class KeyCheck {

    private static final boolean CHECK_VALIDITY = true;
    private static final boolean CHECK_PRIME_DIFFERENCE = true;
    private static final boolean CHECK_PRIME_UNIQUENESS = true;
    private static final boolean CHECK_PRiVATE_EXPONENT = true;

    private static final int RADIX = 10;
    private static final int PRIME_CERTAINITY = 40;
    private static final long STATUS_MESSAGE_AFTER = 20000000000L;

    private static BigInteger exponent;
    private static BigInteger modulus;
    private static BigInteger primeP;
    private static BigInteger primeQ;
    private static boolean publicKeyLoaded = false;

    private static long startTime;
    private static long lastStatusMessageTime;
    private static long keyCount = 0;
    private static long validKeyCount = 0;
    private static long duplicitKeyCount = 0;
    private static BigInteger minPrimeDifference = null;
    private static Set<BigInteger> primes = new HashSet<>();
    private static BigInteger minPrivateExponent = null;

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
            for (int i = 0;; i++) {
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
        primeP = values[0];
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
    
    private static void printStats() {
        System.out.println();
        long elapsedTime = (System.nanoTime() - startTime) / 1000000;
        System.out.println("Analysis completed - " + keyCount
                + " keys processed in " + elapsedTime + " ms");
        if (CHECK_VALIDITY) {
            System.out.println(validKeyCount + " keys are valid, "
                    + (keyCount - validKeyCount) + " invalid");
        } else {
            System.out.println("Key validity not checked");
        }
        if (CHECK_PRIME_UNIQUENESS) {
            if (duplicitKeyCount == 0) {
                System.out.println("All primes are unique");
            } else {
                System.out.println(duplicitKeyCount + " primes are not unique");
            }
        } else {
            System.out.println("Prime uniqueness not checked");
        }
        if (CHECK_PRiVATE_EXPONENT) {
            System.out.println("Minimum private exponent: " + minPrivateExponent.toString(RADIX)
                    + " (bitlength " + minPrivateExponent.bitLength() + ")");
        }
        if (CHECK_PRIME_DIFFERENCE) {
            System.out.println("Minimum prime difference: " + minPrimeDifference.toString(RADIX)
                    + " (bitlength " + minPrimeDifference.bitLength() + ")");
        }
    }
}
