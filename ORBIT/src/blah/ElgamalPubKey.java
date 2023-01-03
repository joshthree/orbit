package blah;

import java.math.BigInteger;
import java.util.Random;

public class ElgamalPubKey implements Pub_Key {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7623685611084207477L;

	@Override
	public byte[] getPublicKey() {
		// TODO Auto-generated method stub  return c as byte array
		return null;
	}

	@Override
	public Ciphertext getEmptyCiphertext() {
		// TODO Auto-generated method stub 
		return encrypt(BigInteger.ONE, BigInteger.ZERO);
	}

	@Override
	public Ciphertext encrypt(BigInteger m, Random rand) {
		// TODO Auto-generated method stub
		return null;
	}
	private Ciphertext encrypt(BigInteger m, BigInteger r) {
		// TODO Auto-generated method stub
		return null;
	}

}
