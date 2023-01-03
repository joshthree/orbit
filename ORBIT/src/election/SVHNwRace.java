package election;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;

import blah.AdditiveCiphertext;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;
import blah.PaillierPubKey;
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
		
		CryptoData miniEnv = raceKey.getZKEnvironment();
		
		BigInteger order = raceKey.getOrder();
		
		for(int i = 0; i < zkpArray.length; i++) {
			BigInteger m2;//2^((v-1)*beta)
			if (i == 0) {
				m2 = BigInteger.ZERO;
			}
			else {
				m2 = BigInteger.TWO.pow((i-1)*bitSeperation);
			}
			if (vote == i) {
				// True Proof.
				//Build cryptodata[] for publicInputs
				publicUnpacked[i] = new CryptoDataArray(new CryptoData[]{ciphertext.getEncryptionProofData(m2)});
				//Build cryptodata[] for secrets
				BigInteger r = ZKToolkit.random(order, rand);
				secretsUnpacked[i] = new CryptoDataArray(new BigInteger[]{r, ephemeral});
				//populate simulatedChallenges[i] with 0.
				simulatedChallenges[i] = new BigIntData(BigInteger.ZERO);
			}
			else {
				// Simulated Proof.
				//Build cryptodata[] for publicInputs
				publicUnpacked[i] = new CryptoDataArray(new CryptoData[]{ciphertext.getEncryptionProofData(m2)});
				//Build cryptodata[] for secrets
				BigInteger r = ZKToolkit.random(order, rand);
				BigInteger z = ZKToolkit.random(order, rand);
				secretsUnpacked[i] = new CryptoDataArray(new BigInteger[]{r, z});
				//populate simulatedChallenges[i] with 0.
				simulatedChallenges[i] = new BigIntData(ZKToolkit.random(order, rand));
			}
			envUnpacked[i] = miniEnv;
		}
		
		secretsUnpacked[secretsUnpacked.length - 1] = new CryptoDataArray(simulatedChallenges); 
		CryptoData env = new CryptoDataArray(envUnpacked);
		CryptoData publicInputs = new CryptoDataArray(publicUnpacked);
		CryptoData secrets = new CryptoDataArray(secretsUnpacked);
		
		try {
			CryptoData[] transcripts = fullProof.proveFiatShamir(publicInputs, secrets, env);
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
		
		
		
		return null;
	}

	@Override
	public boolean verify(EncryptedVote phi) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public EncryptedVote reRandomizeVote(EncryptedVote phi, SecureRandom rand) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public EncryptedVote zero_vote(EncryptedVote phi) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public VoterDecision decrypt(EncryptedVote phi, Additive_Priv_Key p, ObjectInputStream[] in, ObjectOutputStream[] out) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RaceResults tally(ArrayList<EncryptedVote> cPsi, Additive_Priv_Key p, ObjectInputStream[] in,
			ObjectOutputStream[] out, SecureRandom rand) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean confirm(ArrayList<EncryptedVote> cPsi, RaceResults result) {
		// TODO Auto-generated method stub
		return false;
	} //Single Vote Homomorphic No write-in Race
	
	

}