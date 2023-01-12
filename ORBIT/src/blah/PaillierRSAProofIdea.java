package blah;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;

public class PaillierRSAProofIdea {

	public static void main(String[] args) {
		SecureRandom rand0 = new SecureRandom();
		BigInteger seed = new BigInteger(2048, rand0);
		SecureRandom rand = new SecureRandom(seed.toByteArray());

		PaillierPrivKey priv = new PaillierPrivKey(2048, new SecureRandom(seed.toByteArray()));
		PaillierPubKey pub = (PaillierPubKey) priv.getPubKey();
		BigInteger n = pub.getN();

		BigInteger e = BigInteger.valueOf(67);

		BigInteger m = new BigInteger(1000, rand0);
		//			BigInteger m = BigInteger.valueOf(214);

		BigInteger mCurr = BigInteger.ONE;
		BigInteger rsaC = m.modPow(e, n);

		AdditiveCiphertext paillierC0 = pub.encrypt(m, rand);
		AdditiveCiphertext paillierCCurr = pub.encrypt(m, rand);

		BigInteger e2 = e;
		for(int i = e.bitLength()-1; i >= 0; i--) {
			System.out.println(e.testBit(i));
			System.out.println("i = " + i);
			if(i == e.bitLength()-1) {

				paillierCCurr = pub.encrypt(BigInteger.ONE, rand); 
			}
			else {
				paillierCCurr = paillierCCurr.scalarMultiply(mCurr, pub).homomorphicAdd(pub.encrypt(BigInteger.ZERO, rand),pub);
				mCurr = mCurr.modPow(BigInteger.valueOf(2), n);
			}
			if(e.testBit(i)) { //if the ith bit is a 1
				paillierCCurr = paillierCCurr.scalarMultiply(m, pub).homomorphicAdd(pub.encrypt(BigInteger.ZERO, rand),pub);
				mCurr = mCurr.multiply(m).mod(n);
			}

		}
		System.out.println("mCurr = " + mCurr);
		System.out.println("m = " + m);
		System.out.println(rsaC);
		BigInteger blah = priv.decrypt(paillierCCurr).getValue(pub);
		if(n.compareTo(rsaC) <= 0) System.out.println("huh RSA");
		System.out.println(priv.decrypt(paillierCCurr).getValue(pub));
		System.out.println("n = " + n);
		if(n.compareTo(blah) <= 0) System.out.println("huh Paillier");
		
		System.out.println(rsaC.equals(blah));
		
	}
}
