package election;

import java.math.BigInteger;
import java.security.SecureRandom;

import blah.AdditiveCiphertext;
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
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public EncryptedVote rerandomize(BigInteger r) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Object getCiphertext() {
		return cipher.getCipher();
	}

}
