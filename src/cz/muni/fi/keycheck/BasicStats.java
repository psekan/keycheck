package cz.muni.fi.keycheck;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author David Formanek
 */
class BasicStats implements Stats {

    private static final int RADIX = 10;

    private boolean checkValidity = true;
    private boolean checkPrimeDifference = true;
    private boolean checkPrimeUniqueness = true;
    private boolean checkPrivateExponent = true;
    private long keyCount = 0;
    private long validKeyCount = 0;
    private long duplicitKeyCount = 0;
    private BigInteger minPrimeDifference = null;
    private Set<BigInteger> primes = new HashSet<>();
    private BigInteger minPrivateExponent = null;

    public BasicStats(
            boolean checkValidity,
            boolean checkPrimeDifference,
            boolean checkPrimeUniqueness,
            boolean checkPrivateExponent
    ) {
        this.checkValidity = checkValidity;
        this.checkPrimeDifference = checkPrimeDifference;
        this.checkPrimeUniqueness = checkPrimeUniqueness;
        this.checkPrivateExponent = checkPrivateExponent;
    }

    @Override
    public void process(Params params) {
        if (checkValidity) {
            if (params.isValid()) {
                validKeyCount++;
            }
        }
        if (checkPrimeDifference) {
            checkPrimeDifference(params);
        }
        if (checkPrimeUniqueness) {
            checkPrimeUniqueness(params);
        }
        if (checkPrivateExponent) {
            checkPrivateExponent(params);
        }
        keyCount++;
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

    @Override
    public void print() {
        if (checkValidity) {
            System.out.println(validKeyCount + " keys are valid, "
                    + (keyCount - validKeyCount) + " invalid");
        }
        if (checkPrimeUniqueness) {
            if (duplicitKeyCount == 0) {
                System.out.println("All primes are unique");
            } else {
                System.out.println(duplicitKeyCount + " primes are not unique");
            }
        }
        if (checkPrivateExponent && minPrivateExponent != null) {
            System.out.println("Minimum private exponent: " + minPrivateExponent.toString(RADIX)
                    + " (bitlength " + minPrivateExponent.bitLength() + ")");
        }
        if (checkPrimeDifference && minPrimeDifference != null) {
            System.out.println("Minimum prime difference: " + minPrimeDifference.toString(RADIX)
                    + " (bitlength " + minPrimeDifference.bitLength() + ")");
        }
    }
}
