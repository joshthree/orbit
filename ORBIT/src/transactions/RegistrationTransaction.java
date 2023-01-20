package transactions;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import blah.AdditiveElgamalCiphertext;
import blah.AdditiveElgamalPubKey;

public class RegistrationTransaction implements SourceTransaction{
	/**
	 * 
	 */
	private static final long serialVersionUID = -7612729355568619624L;
	private AdditiveElgamalPubKey voterKey;
	private AdditiveElgamalCiphertext password;
	private AdditiveElgamalCiphertext dummyFlag;
	private long position = -1;

	public RegistrationTransaction(AdditiveElgamalPubKey voterKey, AdditiveElgamalCiphertext password, SecureRandom rand) {
		this.voterKey = voterKey;
		dummyFlag = (AdditiveElgamalCiphertext) voterKey.encrypt(BigInteger.ZERO, BigInteger.ZERO);
		this.password = password;
	}
	
	@Override
	public AdditiveElgamalCiphertext getPasswordCiphertext() {
		return password;
	}

	@Override
	public AdditiveElgamalPubKey getVoterPubKey() {
		// TODO Auto-generated method stub
		return voterKey;
	}

	@Override
	public long getPosition() {
		return position;
	}



	@Override
	public void setPosition(long position) {
		this.position = position;
	}

	@Override
	public boolean verifyTransaction(ProcessedBlockchain b) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public AdditiveElgamalCiphertext getDummyFlag() {
		return dummyFlag;
	}

	@Override
	public byte[] getBytes() {
		return ByteBuffer.wrap(new byte[8]).putLong(position).array();
	}

}
