package blah;

import javax.security.auth.Destroyable;

public interface Priv_Key extends Destroyable {
	byte[][] getPrivateKey();
	Pub_Key getPubKey();
	Ciphertext decrypt(Ciphertext c);	
	Ciphertext partialGroupDecrypt(Ciphertext c, Channel[] channels);
	

}
