package cz.muni.fi.keycheck;

import java.math.BigInteger;

/**
 *
 * @author David Formanek
 */
class Params {
    private static final int RADIX = 10;
    private static final int PRIME_CERTAINITY = 40;
    
    private static BigInteger exponent;
    private static BigInteger modulus;
    private static BigInteger p;
    private static BigInteger q;

    public BigInteger getExponent() {
        return exponent;
    }

    public void setExponent(BigInteger exponent) {
        Params.exponent = exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void setModulus(BigInteger modulus) {
        Params.modulus = modulus;
    }

    public BigInteger getP() {
        return p;
    }

    public void setP(BigInteger p) {
        Params.p = p;
    }

    public BigInteger getQ() {
        return q;
    }

    public void setQ(BigInteger q) {
        Params.q = q;
    }
    
    public boolean isValid() {
        boolean isValid = true;
        if (!p.isProbablePrime(PRIME_CERTAINITY)) {
            isValid = false;
            System.out.println(p.toString(RADIX) + " is not a prime");
        }
        if (!q.isProbablePrime(PRIME_CERTAINITY)) {
            isValid = false;
            System.out.println(q.toString(RADIX) + " is not a prime");
        }
        if (!p.multiply(q).equals(modulus)) {
            isValid = false;
            System.out.println("Modulus " + modulus.toString(RADIX) + " has not factors p a q");
        }
        BigInteger phi = modulus.subtract(p).subtract(q).add(BigInteger.ONE);
        if (!phi.gcd(exponent).equals(BigInteger.ONE)) {
            isValid = false;
            System.out.println("Exponent " + exponent.toString(RADIX)
                    + " is not coprime to phi of " + modulus.toString(RADIX));
        }
        return isValid;
    }
    
    public BigInteger getPrimeDifference() {
        return p.subtract(q).abs();
    }
    
    public BigInteger getPrivateExponent() {
        BigInteger phi = modulus.subtract(p).subtract(q).add(BigInteger.ONE);
        return exponent.modInverse(phi);
    }
}
