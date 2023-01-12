package transactions;

import blah.AdditiveCiphertext;
import blah.Additive_Pub_Key;

public interface Transaction {
	AdditiveCiphertext getPasswordCiphertext();
	AdditiveCiphertext getDummyFlag();
	
	
	Additive_Pub_Key getVoterPubKey();

	
	int getPosition();
	void setPosition(int position);

	boolean verifyTransaction(ProcessedBlockchain b);
}
