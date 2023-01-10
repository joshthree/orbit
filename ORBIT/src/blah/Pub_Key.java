package blah;

import java.io.Externalizable;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public interface Pub_Key extends Externalizable {
	byte[] getPublicKey();
	
	Ciphertext getEmptyCiphertext();
	Ciphertext encrypt(BigInteger m, SecureRandom rand);
	
	
}
