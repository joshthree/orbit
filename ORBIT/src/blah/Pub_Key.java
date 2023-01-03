package blah;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Random;

public interface Pub_Key extends Serializable {
	byte[] getPublicKey();
	
	Ciphertext getEmptyCiphertext();
	Ciphertext encrypt(BigInteger m, Random rand);
	
	
}
