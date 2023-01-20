package transactions;

import java.nio.ByteBuffer;

import blah.AdditiveCiphertext;
import blah.Additive_Pub_Key;

public class SpoilTransaction implements SourceTransaction{
	/**
	 * 
	 */
	private static final long serialVersionUID = 6855692716938401733L;
	private Additive_Pub_Key voterKey;
	private BallotTransaction sourceTransaction;
	private long position = -1;
	
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
		return false;
	}

	@Override
	public AdditiveCiphertext getDummyFlag() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public byte[] getBytes() {
		return ByteBuffer.wrap(new byte[8]).putLong(position).array();
	}
	
}
