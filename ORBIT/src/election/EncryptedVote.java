package election;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import blah.Additive_Pub_Key;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface EncryptedVote extends Serializable {
	
	CryptoData[] getProofTranscript();
	
	EncryptedVote rerandomize(SecureRandom rand, Additive_Pub_Key raceKey);
	
	EncryptedVote rerandomize(BigInteger[] r, Additive_Pub_Key raceKey);
	
	Object getCiphertext();

	byte[] getBytes();

	ZKPProtocol getRandomizationProof(Additive_Pub_Key minerKey);
	CryptoData[] getVerificationDataRandomizationProof(EncryptedVote orig, Additive_Pub_Key minerKey);
	CryptoData[] getProverDataRandomizationProof(EncryptedVote orig, BigInteger[] rerandomizer,	Additive_Pub_Key minerKey, SecureRandom rand);

	EncryptedVote withoutProof();



}
 