package blah;

import java.math.BigInteger;

import javax.security.auth.Destroyable;

public interface Priv_Key extends Destroyable {
	BigInteger[] getPrivKey();
	Pub_Key getPubKey();
	Ciphertext decrypt(Ciphertext c);	
	Ciphertext partialGroupDecrypt(Ciphertext c, Channel[] channels);
	

}
