package transactions;

import blah.AdditiveElgamalCiphertext;
import blah.AdditiveElgamalPubKey;

public class RegistrationTransaction implements SourceTransaction{
	private AdditiveElgamalPubKey voterKey;
	private AdditiveElgamalCiphertext password;
	private AdditiveElgamalCiphertext dummyFlag;
	private int position = -1;

	public RegistrationTransaction(AdditiveElgamalPubKey voterKey, AdditiveElgamalPubKey minerKey, AdditiveElgamalCiphertext password) {
		this.voterKey = voterKey;
		dummyFlag = minerKey.encrypt;
		
	}
	
	@Override
	public AdditiveElgamalCiphertext getPasswordCiphertext() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveElgamalPubKey getVoterPubKey() {
		// TODO Auto-generated method stub
		return null;
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
		return false;
	}

	@Override
	public AdditiveElgamalCiphertext getDummyFlag() {
		return dummyFlag;
	}

}
