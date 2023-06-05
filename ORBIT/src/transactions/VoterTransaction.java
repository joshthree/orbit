package transactions;

import java.io.Serializable;

import blah.AdditiveCiphertext;
import blah.Additive_Pub_Key;

public interface VoterTransaction extends Transaction {
	AdditiveCiphertext getPasswordCiphertext(int index);
	int getNumPasswords();
	AdditiveCiphertext getDummyFlag();
	
	
	Additive_Pub_Key getVoterPubKey();

	
	long getPosition();
	void setPosition(long position);

	boolean verifyTransaction(ProcessedBlockchain b);
	
	byte[] getBytes();
}
