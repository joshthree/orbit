package election.singleCipherSVHNw;

import java.math.BigInteger;
import java.security.SecureRandom;

import blah.AdditiveCiphertext;
import blah.Additive_Pub_Key;
import election.EncryptedVote;
import zero_knowledge_proofs.CryptoData.CryptoData;

public class SVHNwEncryptedVote implements EncryptedVote {
	
	private AdditiveCiphertext cipher;
	private CryptoData[] transcript;
	
	public SVHNwEncryptedVote(AdditiveCiphertext cipher, CryptoData[] transcript) {
		this.cipher = cipher;
		this.transcript = transcript;
	}

	@Override
	public CryptoData[] getProofTranscript() {
		return transcript.clone();
	}

	@Override
	public EncryptedVote rerandomize(SecureRandom rand) {
		BigInteger r = ((Additive_Pub_Key) (cipher.getPub_Key())).generateEphemeral(rand);
		return rerandomize(new BigInteger[] {r});
	}

	@Override
	public EncryptedVote rerandomize(BigInteger[] r) {
		
		//Rerandomize
		AdditiveCiphertext cipher2 = (AdditiveCiphertext) cipher.rerandomize(r[0]);
		
		return new SVHNwEncryptedVote(cipher2, null);
	}

	@Override
	public Object getCiphertext() {
		return cipher;
	}

}
