package transactions;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import blah.AdditiveCiphertext;
import blah.AdditiveElgamalCiphertext;
import blah.AdditiveElgamalPrivKey;
import blah.Additive_Pub_Key;
import zero_knowledge_proofs.CryptoData.CryptoData;

public class SpoilTransaction implements SourceTransaction{
	/**
	 * 
	 */
	private static final long serialVersionUID = 6855692716938401733L;
	private Additive_Pub_Key voterKey; 
	private BallotTransaction sourceTransaction; 
	private AdditiveElgamalCiphertext dummyFlag;
	private AdditiveElgamalCiphertext[] password;
	private CryptoData[] signature;
	private long position = -1;
	
	public SpoilTransaction(AdditiveElgamalPrivKey voterKey, AdditiveElgamalCiphertext[] password, AdditiveElgamalCiphertext dummyFlag, BallotTransaction source, SecureRandom rand) {
		this.dummyFlag = dummyFlag;
		sourceTransaction = source;
		this.password = password;
		this.voterKey = voterKey.getPubKey();
		//TODO:  Not complete:  Needs to prove ownership of ballot and requires ballot, just for testing.
	}
	
	public BallotTransaction getSourceTransaction() {
		return sourceTransaction;
	}

	@Override
	public AdditiveCiphertext getPasswordCiphertext(int index) {
		return password[index];
	}

	@Override
	public Additive_Pub_Key getVoterPubKey() {
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
		return false;
	}

	@Override
	public AdditiveCiphertext getDummyFlag() {
		// TODO Auto-generated method stub
		return dummyFlag;
	}

	@Override
	public byte[] getBytes() {
		return ByteBuffer.wrap(new byte[8]).putLong(position).array();
	}

	@Override
	public int getNumPasswords() {
		return password.length;
	}
}
