package election;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import blah.Additive_Pub_Key;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface EncryptedVote extends Serializable {
	
	CryptoData[] getProofTranscript();
	
	EncryptedVote rerandomize(SecureRandom rand, Additive_Pub_Key raceKey);
	
	EncryptedVote rerandomize(BigInteger[] r, Additive_Pub_Key raceKey);
	
	Object getCiphertext();

}
 