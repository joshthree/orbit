package blah;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public abstract class Ciphertext implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -8437241215736240995L;

	public abstract Object getCipher();

	public abstract BigInteger getValue();
	
	public abstract Pub_Key getPub_Key();
	

	public abstract Ciphertext rerandomize(BigInteger r);
	public abstract Ciphertext rerandomize(SecureRandom rand);
}
