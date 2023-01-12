package election;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.CryptoData.CryptoData;

public interface EncryptedVote extends Serializable {
	
	CryptoData[] getProofTranscript();
	
	EncryptedVote rerandomize(SecureRandom rand);
	
	EncryptedVote rerandomize(BigInteger[] r);
	
	Object getCiphertext();

}
 