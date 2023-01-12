package blah;

import java.math.BigInteger;

public interface Additive_Priv_Key extends Priv_Key {
	@Override
	Additive_Pub_Key getPubKey();
	@Override
	BigInteger[] getPrivKey();
	@Override
	AdditiveCiphertext decrypt(Ciphertext c);	
	@Override
	AdditiveCiphertext partialGroupDecrypt(Ciphertext c, Channel[] channels);
	

}
