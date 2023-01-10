package election.multiCipherSVHNw;

import java.math.BigInteger;
import java.security.SecureRandom;

import blah.AdditiveCiphertext;
import blah.AdditiveElgamalCiphertext;
import blah.Additive_Pub_Key;
import election.EncryptedVote;
import zero_knowledge_proofs.CryptoData.CryptoData;

public class SVHNwEncryptedVoteMulti implements EncryptedVote {
	
	private AdditiveCiphertext[] cipher;
	private CryptoData[] transcript;
	
	public SVHNwEncryptedVoteMulti(AdditiveCiphertext[] cipher, CryptoData[] transcript) {
		this.cipher = cipher;
		this.transcript = transcript;
	}

	@Override
	public CryptoData[] getProofTranscript() {
		return transcript.clone();
	}

	@Override
	public EncryptedVote rerandomize(SecureRandom rand) {
		BigInteger[] r = new BigInteger[cipher.length];
		for(int i = 0; i < r.length; i++) {
			r[i] = ((Additive_Pub_Key) (cipher[i].getPub_Key())).generateEphemeral(rand);
		}
		return rerandomize(r);
	}

	@Override
	public EncryptedVote rerandomize(BigInteger[] r) {
		AdditiveCiphertext[] newCiphers = new AdditiveCiphertext[cipher.length];
		for(int i = 0; i < r.length; i++) {
		//Rerandomize
			newCiphers[i] = ((AdditiveCiphertext) cipher[i]).rerandomize(r[i]);
		}
		return new SVHNwEncryptedVoteMulti(newCiphers, null);
	}

	@Override
	public Object getCiphertext() {
		return cipher;
	}

}
