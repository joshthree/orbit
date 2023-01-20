package election.multiCipherSVHNw;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.util.Arrays;

import blah.AdditiveCiphertext;
import blah.AdditiveElgamalCiphertext;
import blah.Additive_Pub_Key;
import election.EncryptedVote;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class SVHNwEncryptedVoteMulti implements EncryptedVote {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -8695519138430315100L;
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
	public EncryptedVote rerandomize(SecureRandom rand, Additive_Pub_Key raceKey) {
		BigInteger[] r = new BigInteger[cipher.length];
		for(int i = 0; i < r.length; i++) {
			r[i] = raceKey.generateEphemeral(rand);
		}
		return rerandomize(r,  raceKey);
	}

	@Override
	public EncryptedVote rerandomize(BigInteger[] r, Additive_Pub_Key raceKey) {
		AdditiveCiphertext[] newCiphers = new AdditiveCiphertext[cipher.length];
		for(int i = 0; i < r.length; i++) {
		//Rerandomize
			newCiphers[i] = ((AdditiveCiphertext) cipher[i]).rerandomize(r[i], raceKey);
		}
		return new SVHNwEncryptedVoteMulti(newCiphers, null);
	}
	
	@Override
	public ZKPProtocol getRandomizationProof(Additive_Pub_Key minerKey) {
		ZKPProtocol[] toReturn = new ZKPProtocol[cipher.length];
		ZKPProtocol inner = minerKey.getZKPforRerandomization();
		for(int i = 0; i < toReturn.length; i++) {
			toReturn[i] = inner;
		}
		
		return new ZeroKnowledgeAndProver(toReturn);
	}

	@Override
	public Object getCiphertext() {
		return cipher;
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		byte[][] toReturn = new byte[cipher.length + transcript.length][];
		for(int i = 0; i < cipher.length; i++) {
			toReturn[i] = cipher[i].getBytes();
		}
		for(int i = 0; i < transcript.length; i++) {
			toReturn[i+cipher.length] = transcript[i].getBytes();
		}
		return Arrays.concatenate(toReturn);
	}

	@Override
	public CryptoData[] getVerificationDataRandomizationProof(EncryptedVote orig, Additive_Pub_Key minerKey) {
		CryptoData[] toReturn = new CryptoData[2];
		CryptoData[] pub = new CryptoData[cipher.length];
		CryptoData[] env = new CryptoData[cipher.length];
		for(int i = 0; i < cipher.length; i++) {
			CryptoData[] inner = cipher[i].getRerandomizationVerifierData(((AdditiveCiphertext[])orig.getCiphertext())[i], minerKey);
			pub[i] = inner[0];
			env[i] = inner[1];
		}

		toReturn[0] = new CryptoDataArray(pub);
		toReturn[1] = new CryptoDataArray(env);
		return toReturn;
	}

	@Override
	public CryptoData[] getProverDataRandomizationProof(EncryptedVote orig, BigInteger[] rerandomizer, Additive_Pub_Key minerKey, SecureRandom rand) {
		CryptoData[] toReturn = new CryptoData[3];
		CryptoData[] pub = new CryptoData[cipher.length];
		CryptoData[] sec = new CryptoData[cipher.length];
		CryptoData[] env = new CryptoData[cipher.length];
		for(int i = 0; i < cipher.length; i++) {
			CryptoData[] inner;
			if(rerandomizer == null) {
				inner = cipher[i].getRerandomizationProverData(((AdditiveCiphertext[])orig.getCiphertext())[i], null, rand, minerKey);
			}
			else inner = cipher[i].getRerandomizationProverData(((AdditiveCiphertext[])orig.getCiphertext())[i], rerandomizer[i], rand, minerKey);
			pub[i] = inner[0];
			sec[i] = inner[1];
			env[i] = inner[2];
		}
		toReturn[0] = new CryptoDataArray(pub);
		toReturn[1] = new CryptoDataArray(sec);
		toReturn[2] = new CryptoDataArray(env);
		return toReturn;
	}

	@Override
	public EncryptedVote withoutProof() {
		// TODO Auto-generated method stub
		return new SVHNwEncryptedVoteMulti(cipher, null);
	}

}
