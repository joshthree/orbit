package blah;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.util.InputMismatchException;

import javax.security.auth.DestroyFailedException;

public class PaillierPrivKey implements Additive_Priv_Key{
	private BigInteger lambda;
	private BigInteger mu;
	
	private BigInteger n;
	private BigInteger n2;
	private BigInteger g;
	
	private boolean isDestroyed = false;
	
	
	private PaillierPubKey pubKey;
	
	public PaillierPrivKey(int bits, SecureRandom rand) {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(bits, rand);
			KeyPair keys = keyGen.genKeyPair();
			RSAPrivateCrtKey privKey = (RSAPrivateCrtKey) keys.getPrivate();

			BigInteger pm1 = privKey.getPrimeP().subtract(BigInteger.ONE);
			BigInteger qm1 = privKey.getPrimeQ().subtract(BigInteger.ONE);
			n = privKey.getModulus();
			n2 = n.pow(2);
	        BigInteger mul = pm1.multiply(qm1);
	        BigInteger gcd = pm1.gcd(qm1);
//	        Util.destroyBigInteger(pm1);
//	        Util.destroyBigInteger(qm1);
	        pm1 = null;
	        qm1 = null;
//	        Util.destroyBigInteger(privKey.getPrimeP());
	        lambda = mul.divide(gcd);
			
			g = n.add(BigInteger.ONE);
			try {
				mu = lFunction(g.modPow(lambda, n2), n).modInverse(n);
			}catch(Exception e) {
			}
			while(mu == null) {
				g = new BigInteger(n.bitLength(), rand);
				try {
					BigInteger temp = g.modPow(lambda, n2);
					BigInteger temp2 = lFunction(temp, n);
					Util.destroyBigInteger(temp);
					
					mu = lFunction(temp2.modInverse(n), n);
					Util.destroyBigInteger(temp2);
					
				}catch(Exception e) {
					System.out.println("Error");
				}
			}	
			pubKey = new PaillierPubKey(n, n2 ,g);
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	private BigInteger lFunction(BigInteger x, BigInteger n) {
		BigInteger temp = (x.subtract(BigInteger.ONE)).divide(n);
		return temp;
	}

	@Override
	public BigInteger[] getPrivKey() {
		// TODO Auto-generated method stub
		return new BigInteger[] {mu, lambda};
	}

	@Override
	public Additive_Pub_Key getPubKey() {
		return new PaillierPubKey(pubKey);
	}
	@Override
	public AdditiveCiphertext decrypt(Ciphertext c) {
		if(!pubKey.equals(c.getPub_Key())) {
			throw new InputMismatchException("Mismatched Keys");
		}
		PaillierCiphertext cipher = (PaillierCiphertext) c;	
		return new PaillierCiphertext((lFunction(cipher.getCipher().modPow(lambda,n2), n).multiply(mu)).mod(n), null);
	}
	@Override
	public AdditiveCiphertext partialGroupDecrypt(Ciphertext c, Channel[] channels) {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public void destroy() {
		Util.destroyBigInteger(lambda);
		Util.destroyBigInteger(mu);
		isDestroyed = true;
		
	}
	@Override
	public boolean isDestroyed() {
		return isDestroyed;
	}
	
}
