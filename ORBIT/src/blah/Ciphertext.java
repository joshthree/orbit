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

	public abstract Object getCipher(Pub_Key pub);

	public abstract BigInteger getValue(Pub_Key pub);
	
}
