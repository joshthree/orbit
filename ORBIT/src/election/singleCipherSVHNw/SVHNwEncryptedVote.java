package election.singleCipherSVHNw;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

import blah.AdditiveCiphertext;
import blah.Additive_Pub_Key;
import election.EncryptedVote;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;

public class SVHNwEncryptedVote implements EncryptedVote {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -2151827978056330592L;
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
	public EncryptedVote rerandomize(SecureRandom rand, Additive_Pub_Key raceKey) {
		BigInteger r = raceKey.generateEphemeral(rand);
		return rerandomize(new BigInteger[] {r}, raceKey);
	}

	@Override
	public EncryptedVote rerandomize(BigInteger[] r, Additive_Pub_Key raceKey) {
		
		//Rerandomize
		AdditiveCiphertext cipher2 = (AdditiveCiphertext) cipher.rerandomize(r[0], raceKey);
		
		return new SVHNwEncryptedVote(cipher2, null);
	}

	@Override
	public Object getCiphertext() {
		return cipher;
	}
	
	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		byte[][] toReturn = new byte[1 + transcript.length][];
		toReturn[0] = cipher.getBytes();
		for(int i = 0; i < transcript.length; i++) {
			toReturn[i+1] = transcript[i].getBytes();
		}
		return Arrays.concatenate(toReturn);
	}

	@Override
	public ZKPProtocol getRandomizationProof(Additive_Pub_Key minerKey) {
		// TODO Auto-generated method stub
		return minerKey.getZKPforRerandomization();
	}

	@Override
	public CryptoData[] getVerificationDataRandomizationProof(EncryptedVote orig, Additive_Pub_Key minerKey) {
		// TODO Auto-generated method stub
		return cipher.getRerandomizationVerifierData((AdditiveCiphertext) orig.getCiphertext(), minerKey);
	}

	@Override
	public CryptoData[] getProverDataRandomizationProof(EncryptedVote orig, BigInteger[] rerandomizer,
			Additive_Pub_Key raceKey, SecureRandom rand) {
		// TODO Auto-generated method stub
		if(rerandomizer == null) {
			return cipher.getRerandomizationProverData((AdditiveCiphertext) orig.getCiphertext(), null, rand, raceKey);
		}
		return cipher.getRerandomizationProverData((AdditiveCiphertext) orig.getCiphertext(), rerandomizer[0], rand, raceKey);
	}

	@Override
	public EncryptedVote withoutProof() {
		// TODO Auto-generated method stub
		return new SVHNwEncryptedVote(cipher, null);
	}

}
