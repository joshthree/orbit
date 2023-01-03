package election;

import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.CryptoData.CryptoData;

public interface EncryptedVote {
	
	CryptoData[] getProofTranscript();
	
	EncryptedVote rerandomize(SecureRandom rand);
	
	EncryptedVote rerandomize(BigInteger r);
	
	Object getCiphertext();

}
 