package blah;

import java.math.BigInteger;
import java.util.Random;

public class AdditiveElgamal extends AdditiveCiphertext {

	/**
	 * 
	 */
	private static final long serialVersionUID = 508970794714992682L;

	@Override
	public AdditiveCiphertext partialDecrypt(Ciphertext c, Priv_Key privKey) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext partialGroupDecrypt(Ciphertext c, Priv_Key privKey, Channel[] channels) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext homomorphicAdd(AdditiveCiphertext toAdd) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext scalarMultiply(BigInteger toMultiply) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext getEmptyEncryption() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected void mutableAdd(AdditiveCiphertext toAdd) {
		// TODO Auto-generated method stub

	}

	@Override
	public BigInteger fullDecrypt(Ciphertext partialDecrypt) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Ciphertext rerandomize(BigInteger r) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Ciphertext rerandomize(Random rand) {
		// TODO Auto-generated method stub
		return null;
	}

}
