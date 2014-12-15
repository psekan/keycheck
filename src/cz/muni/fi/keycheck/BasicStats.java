package cz.muni.fi.keycheck;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author David Formanek
 */
class BasicStats {

    private static final boolean CHECK_VALIDITY = false;
    private static final boolean CHECK_PRIME_DIFFERENCE = false;
    private static final boolean CHECK_PRIME_UNIQUENESS = false;
    private static final boolean CHECK_PRiVATE_EXPONENT = false;

    private long validKeyCount = 0;
    private long duplicitKeyCount = 0;
    private BigInteger minPrimeDifference = null;
    private Set<BigInteger> primes = new HashSet<>();
    private BigInteger minPrivateExponent = null;

    void process(Params params) {
        if (CHECK_VALIDITY) {
            if (params.isValid()) {
                validKeyCount++;
            }
        }
        if (CHECK_PRIME_DIFFERENCE) {
            checkPrimeDifference(params);
        }
        if (CHECK_PRIME_UNIQUENESS) {
            checkPrimeUniqueness(params);
        }
        if (CHECK_PRiVATE_EXPONENT) {
            checkPrivateExponent(params);
        }
    }

    private void checkPrimeDifference(Params params) {
        BigInteger difference = params.getPrimeDifference();
        if (minPrimeDifference == null || minPrimeDifference.compareTo(difference) > 0) {
            minPrimeDifference = difference;
        }
    }

    private void checkPrimeUniqueness(Params params) {
        if (!primes.add(params.getP())) {
            duplicitKeyCount++;
            System.out.println("Prime " + params.getP() + " is duplicit!");
        }
        if (!primes.add(params.getQ())) {
            duplicitKeyCount++;
            System.out.println("Prime " + params.getQ() + " is duplicit!");
        }
    }

    private void checkPrivateExponent(Params params) {
        BigInteger exponent = params.getPrivateExponent();
        if (minPrivateExponent == null || minPrivateExponent.compareTo(exponent) > 0) {
            minPrivateExponent = exponent;
        }
    }

    void print(long keyCount, int radix) {
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
            System.out.println("Minimum private exponent: " + minPrivateExponent.toString(radix)
                    + " (bitlength " + minPrivateExponent.bitLength() + ")");
        }
        if (CHECK_PRIME_DIFFERENCE && minPrimeDifference != null) {
            System.out.println("Minimum prime difference: " + minPrimeDifference.toString(radix)
                    + " (bitlength " + minPrimeDifference.bitLength() + ")");
        }
    }
}
