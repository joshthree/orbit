package transactions;

import java.math.BigInteger;
import java.security.SecureRandom;

import blah.AdditiveElgamalCiphertext;
import blah.AdditiveElgamalPubKey;
import blah.Additive_Pub_Key;

public class RegistrationTransaction implements SourceTransaction{
	private AdditiveElgamalPubKey voterKey;
	private AdditiveElgamalCiphertext password;
	private AdditiveElgamalCiphertext dummyFlag;
	private int position = -1;

	public RegistrationTransaction(AdditiveElgamalPubKey voterKey, AdditiveElgamalCiphertext password, AdditiveElgamalPubKey minerKey, SecureRandom rand) {
		this.voterKey = voterKey;
		dummyFlag = (AdditiveElgamalCiphertext) minerKey.encrypt(BigInteger.ZERO, BigInteger.ZERO);
		Additive_Pub_Key origPubKey = voterKey.combineKeys(minerKey);
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
	public int getPosition() {
		return position;
	}



	@Override
	public void setPosition(int position) {
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

}
