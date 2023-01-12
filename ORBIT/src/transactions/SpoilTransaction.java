package transactions;

import blah.AdditiveCiphertext;
import blah.Additive_Pub_Key;

public class SpoilTransaction implements SourceTransaction{
	private Additive_Pub_Key voterKey;
	private BallotTransaction sourceTransaction;
	private int position = -1;
	
	public BallotTransaction getSourceTransaction() {
		return null;
	}

	@Override
	public AdditiveCiphertext getPasswordCiphertext() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Additive_Pub_Key getVoterPubKey() {
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
	public AdditiveCiphertext getDummyFlag() {
		// TODO Auto-generated method stub
		return null;
	}
}
