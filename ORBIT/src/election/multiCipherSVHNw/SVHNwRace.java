package election.multiCipherSVHNw;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import blah.AdditiveCiphertext;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;
import election.EncryptedVote;
import election.Race;
import election.RaceResults;
import election.VoterDecision;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class SVHNwRace implements Race{ //Single Vote Homomorphic No write-in Race 
	
	private String description;
	private int numCandidates;
	private Additive_Pub_Key raceKey;
	private int bitSeperation;
	private ZKPProtocol voteProof;
	
	public SVHNwRace (String description, int numCandidates, Additive_Pub_Key raceKey, int bitSeperation) {
		this.description = description;
		this.numCandidates = numCandidates;
		this.raceKey = raceKey;
		this.bitSeperation = bitSeperation;
	}

	@Override
	public EncryptedVote vote(VoterDecision v, SecureRandom rand) {
		SVHNwVoterDecision v2 = (SVHNwVoterDecision)v;
		int vote = v2.getDecision();
		BigInteger m;//2^((v-1)*beta)
		if (vote == 0) {
			m = BigInteger.ZERO;
		}
		else {
			m = BigInteger.TWO.pow((vote-1)*bitSeperation);
		}
		BigInteger ephemeral = raceKey.generateEphemeral(rand);
		AdditiveCiphertext ciphertext =  raceKey.encrypt(m, ephemeral);
		
		ZKPProtocol baseProof = raceKey.getZKPforProofOfEncryption();
		
		ZKPProtocol[] zkpArray = new ZKPProtocol[numCandidates+1];
		
		for(int i = 0; i < zkpArray.length; i++) {
			zkpArray[i] = baseProof;
		}
		ZKPProtocol fullProof = new ZeroKnowledgeOrProver(zkpArray);
		
		CryptoData[] envUnpacked = new CryptoData[zkpArray.length];
		CryptoData[] publicUnpacked = new CryptoData[zkpArray.length];
		CryptoData[] secretsUnpacked = new CryptoData[zkpArray.length + 1];
		CryptoData[] simulatedChallenges = new CryptoData[zkpArray.length];
		
		BigInteger order = raceKey.getOrder();
		
		for(int i = 0; i < zkpArray.length; i++) {
			BigInteger m2;//2^((v-1)*beta)
			if (i == 0) {
				m2 = BigInteger.ZERO;
			}
			else {
				m2 = BigInteger.TWO.pow((i-1)*bitSeperation);
			}
			CryptoData[] proofInputs;
			if (vote == i) {
				// True Proof.
				proofInputs = ciphertext.getEncryptionProverData(m2, ephemeral, rand);
				simulatedChallenges[i] = new BigIntData(BigInteger.ZERO);
			}
			else {
				// simulated proof
				proofInputs = ciphertext.getEncryptionProverData(m2, null, rand);
				simulatedChallenges[i] = new BigIntData(ZKToolkit.random(order, rand));
			}
			publicUnpacked[i] = proofInputs[0];
			secretsUnpacked[i] = proofInputs[1];
			envUnpacked[i] = proofInputs[2];
		}
		
		secretsUnpacked[secretsUnpacked.length - 1] = new CryptoDataArray(simulatedChallenges); 
		CryptoData env = new CryptoDataArray(envUnpacked);
		CryptoData publicInputs = new CryptoDataArray(publicUnpacked);
		CryptoData secrets = new CryptoDataArray(secretsUnpacked);
		CryptoData[] transcripts = null;
		try {
			transcripts = fullProof.proveFiatShamir(publicInputs, secrets, env);
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MultipleTrueProofException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoTrueProofException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ArraySizesDoNotMatchException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		//For each proof in fullProof
		
			//Build enviroment
			//Build public information
			//build secrets
		//Combine environment
		//Combine public information
		//Combine secrets
		
		
		
		return new SVHNwEncryptedVote (ciphertext, transcripts);
	}

	@Override
	public boolean verify(EncryptedVote phi) {
		SVHNwEncryptedVote phi2 = (SVHNwEncryptedVote) phi;
		AdditiveCiphertext cipher = (AdditiveCiphertext) phi2.getCiphertext();
		CryptoData[] transcript = phi2.getProofTranscript();
		
		CryptoData[] envUnpacked = new CryptoData[numCandidates+1];
		CryptoData[] publicUnpacked = new CryptoData[numCandidates+1];
		
		for(int i = 0; i < numCandidates+1; i++) {
			BigInteger m2;//2^((v-1)*beta)
			if (i == 0) {
				m2 = BigInteger.ZERO;
			}
			else {
				m2 = BigInteger.TWO.pow((i-1)*bitSeperation);
			}
			// True Proof.
			//Build cryptodata[] for publicInputs
			CryptoData[] vInputs = cipher.getEncryptionVerifierData(m2);
			publicUnpacked[i] = vInputs[0];
		
			envUnpacked[i] = vInputs[1];
		}
		
		CryptoData env = new CryptoDataArray(envUnpacked);
		CryptoData publicInputs = new CryptoDataArray(publicUnpacked);
		
		ZKPProtocol baseProof = raceKey.getZKPforProofOfEncryption();
		
		ZKPProtocol[] zkpArray = new ZKPProtocol[numCandidates+1];
		
		for(int i = 0; i < zkpArray.length; i++) {
			zkpArray[i] = baseProof;
		}
		
		ZKPProtocol fullProof = new ZeroKnowledgeOrProver(zkpArray);
		
		try {
			return fullProof.verifyFiatShamir(publicInputs, transcript[0], transcript[1], env);
		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e) {
			e.printStackTrace();
			return false;
		}
	}

	@Override
	public EncryptedVote reRandomizeVote(EncryptedVote phi, SecureRandom rand) {
		// TODO Auto-generated method stub
		//Maybe not needed potentially remove.
		return null;
	}

	@Override
	public EncryptedVote zero_vote(EncryptedVote phi) {
		AdditiveCiphertext zeroVote = raceKey.getEmptyCiphertext();
		return new SVHNwEncryptedVote(zeroVote, null);
	}

	@Override
	public VoterDecision decrypt(EncryptedVote phi, Additive_Priv_Key p, ObjectInputStream[] in, ObjectOutputStream[] out) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RaceResults tally(ArrayList<EncryptedVote> cPsi, Additive_Priv_Key p, ObjectInputStream[] in,
			ObjectOutputStream[] out, SecureRandom rand) {
		AdditiveCiphertext bigPsiprime = raceKey.getEmptyCiphertext();
		for (int i = 0; i < cPsi.size(); i++) {
			bigPsiprime = bigPsiprime.homomorphicAdd((AdditiveCiphertext)(cPsi.get(i).getCiphertext()));
		}
		System.out.println("resulting ciphertext ");
		System.out.println(bigPsiprime);
		return null;
	}

	@Override
	public boolean confirm(ArrayList<EncryptedVote> cPsi, RaceResults result) {
		// TODO Auto-generated method stub
		return false;
	} //Single Vote Homomorphic No write-in Race
	
	

}