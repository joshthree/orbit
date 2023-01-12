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
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class SVHNwRaceMulti implements Race{ //Single Vote Homomorphic No write-in Race 
	
	private String description;
	private int numCandidates;
	private Additive_Pub_Key raceKey;
	private ZKPProtocol voteProof;
	
	public SVHNwRaceMulti (String description, int numCandidates, Additive_Pub_Key raceKey) {
		this.description = description;
		this.numCandidates = numCandidates;
		this.raceKey = raceKey;
	}

	@Override
	public EncryptedVote vote(VoterDecision v, SecureRandom rand) {
		BigInteger order = raceKey.getOrder();
		
		SVHNwVoterDecisionMulti v2 = (SVHNwVoterDecisionMulti)v;
		int vote = v2.getDecision();
		
		BigInteger m;//2^((v-1)*beta)
		AdditiveCiphertext[] ciphers = new AdditiveCiphertext[numCandidates];
		BigInteger[] ephemerals = new BigInteger[numCandidates];
		for(int i = 0; i < numCandidates; i++) {
			ephemerals[i] = raceKey.generateEphemeral(rand);
			if(vote == i+1) {
				ciphers[i] =  raceKey.encrypt(BigInteger.ONE, ephemerals[i]);
			} else {
				ciphers[i] =  raceKey.encrypt(BigInteger.ZERO, ephemerals[i]);
			}
		}
		int bitSeparation = 2;
		ZKPProtocol baseProof = raceKey.getZKPforProofOfEncryption();
		ZKPProtocol[] ors = new ZKPProtocol[] {baseProof, baseProof};
		
		
		//Prove each ciphertext is 0 or 1
		
		
		CryptoData[] publicInputsZeroOrOne = new CryptoData[numCandidates];
		CryptoData[] secretInputsZeroOrOne = new CryptoData[numCandidates];
		CryptoData[] environmentZeroOrOne = new CryptoData[numCandidates];
		
		for (int i = 0; i < numCandidates; i++){
			CryptoData[] pub = new CryptoData[2];
			CryptoData[] sec = new CryptoData[3];
			CryptoData[] env = new CryptoData[2];
			CryptoData[] simChals = new CryptoData[2];
			
			CryptoData[] in0;
			CryptoData[] in1;
			CryptoData simChal = new BigIntData(ZKToolkit.random(raceKey.getOrder(), rand));
			if(vote != i+1) {	//if this is the vote
				simChals[0] = new BigIntData(null);
				simChals[1] = simChal;
				in0 = ciphers[i].getEncryptionProverData(BigInteger.ZERO, ephemerals[i], rand);
				in1 = ciphers[i].getEncryptionProverData(BigInteger.ONE, null, rand);
			} else {
				simChals[0] = simChal;
				simChals[1] = new BigIntData(null);
				in0 = ciphers[i].getEncryptionProverData(BigInteger.ZERO, null, rand);
				in1 = ciphers[i].getEncryptionProverData(BigInteger.ONE, ephemerals[i], rand);
			}
			pub[0] = in0[0];
			pub[1] = in1[0];
			publicInputsZeroOrOne[i] = new CryptoDataArray(pub);
			
			sec[0] = in0[1];
			sec[1] = in1[1];
			sec[2] = new CryptoDataArray(simChals);
			secretInputsZeroOrOne[i] = new CryptoDataArray(sec);

			env[0] = in0[2];
			env[1] = in1[2];
			environmentZeroOrOne[i] = new CryptoDataArray(env);
		}
		
		//Combine ciphertexts
		AdditiveCiphertext ciphertext = ciphers[0];
		BigInteger combinedEphemeral = ephemerals[0];
		for(int i = 1; i < ciphers.length; i++) {
			BigInteger toMultiply = BigInteger.TWO.pow(i*bitSeparation);
			AdditiveCiphertext tempCipher = ciphers[i].scalarMultiply(BigInteger.TWO.pow(i*bitSeparation));
			BigInteger tempEphemeral = tempCipher.scalarMultiplyEphemeral(toMultiply, ephemerals[i]);
			ciphertext = ciphertext.homomorphicAdd(tempCipher);
			combinedEphemeral = ciphertext.homomorphicAddEphemeral(combinedEphemeral, tempEphemeral);
		}
		
		//Prove ciphertext combination is one of numCandidates+1 values.		
		ZKPProtocol[] orsCombined = new ZKPProtocol[numCandidates];
		for(int i = 0; i < orsCombined.length; i++) {
			orsCombined[i] = new ZeroKnowledgeOrProver(ors, order);
		}

		ZKPProtocol[] zkpArray = new ZKPProtocol[numCandidates+1];
		

		for(int i = 0; i < zkpArray.length; i++) {
			zkpArray[i] = baseProof;
		}
		ZKPProtocol fullProof = new ZeroKnowledgeAndProver(new ZKPProtocol[] {new ZeroKnowledgeAndProver(orsCombined), new ZeroKnowledgeOrProver(zkpArray, order)});
		
		
		CryptoData[] envUnpacked = new CryptoData[zkpArray.length];
		CryptoData[] publicUnpacked = new CryptoData[zkpArray.length];
		CryptoData[] secretsUnpacked = new CryptoData[zkpArray.length + 1];
		CryptoData[] simulatedChallenges = new CryptoData[zkpArray.length];
		
		
		for(int i = 0; i < zkpArray.length; i++) {
			BigInteger m2;//2^((v-1)*beta)
			if (i == 0) {
				m2 = BigInteger.ZERO;
			}
			else {
				m2 = BigInteger.TWO.pow((i-1)*bitSeparation);
			}
			CryptoData[] proofInputs;
			if (vote == i) {
				// True Proof.
				proofInputs = ciphertext.getEncryptionProverData(m2, combinedEphemeral, rand);
				simulatedChallenges[i] = new BigIntData(null);
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
		CryptoData envCombined = new CryptoDataArray(envUnpacked);
		CryptoData publicInputsCombined = new CryptoDataArray(publicUnpacked);
		CryptoData secretsCombined = new CryptoDataArray(secretsUnpacked);
		
		CryptoData env = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(environmentZeroOrOne), envCombined});
		CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(publicInputsZeroOrOne), publicInputsCombined});
		CryptoData secrets = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(secretInputsZeroOrOne), secretsCombined});
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
		
		
		
		return new SVHNwEncryptedVoteMulti (ciphers, transcripts);
	}

	@Override
	public boolean verify(EncryptedVote psi) {
		BigInteger order = raceKey.getOrder();
		
		SVHNwEncryptedVoteMulti psi2 = (SVHNwEncryptedVoteMulti) psi;
		AdditiveCiphertext[] ciphers = (AdditiveCiphertext[]) psi2.getCiphertext();
		CryptoData[] transcript = psi2.getProofTranscript();
		int bitSeparation = 2;
		CryptoData[] publicInputsZeroOrOne = new CryptoData[numCandidates];
		CryptoData[] environmentZeroOrOne = new CryptoData[numCandidates];
		
		for (int i = 0; i < numCandidates; i++){
			CryptoData[] pub = new CryptoData[2];
			CryptoData[] env = new CryptoData[2];
			
			CryptoData[] in0;
			CryptoData[] in1;
			in0 = ciphers[i].getEncryptionVerifierData(BigInteger.ZERO);
			in1 = ciphers[i].getEncryptionVerifierData(BigInteger.ONE);
			
			pub[0] = in0[0];
			pub[1] = in1[0];
			publicInputsZeroOrOne[i] = new CryptoDataArray(pub);
			

			env[0] = in0[1];
			env[1] = in1[1];
			environmentZeroOrOne[i] = new CryptoDataArray(env);
		}
		CryptoData[] envUnpacked = new CryptoData[numCandidates+1];
		CryptoData[] publicUnpacked = new CryptoData[numCandidates+1];
		

		//Combine ciphertexts
		AdditiveCiphertext ciphertext = ciphers[0];
		for(int i = 1; i < ciphers.length; i++) {
			BigInteger toMultiply = BigInteger.TWO.pow(i*bitSeparation);
			AdditiveCiphertext tempCipher = ciphers[i].scalarMultiply(BigInteger.TWO.pow(i*bitSeparation));
			ciphertext = ciphertext.homomorphicAdd(tempCipher);
		}
		for(int i = 0; i < numCandidates+1; i++) {
			BigInteger m2;//2^((v-1)*beta)
			if (i == 0) {
				m2 = BigInteger.ZERO;
			}
			else {
				m2 = BigInteger.TWO.pow((i-1)*bitSeparation);
			}
			// True Proof.
			//Build cryptodata[] for publicInputs
			CryptoData[] vInputs = ciphertext.getEncryptionVerifierData(m2);
			publicUnpacked[i] = vInputs[0];
		
			envUnpacked[i] = vInputs[1];
		}

		CryptoData envCombined = new CryptoDataArray(envUnpacked);
		CryptoData publicInputsCombined = new CryptoDataArray(publicUnpacked);
		
		ZKPProtocol baseProof = raceKey.getZKPforProofOfEncryption();
		
		ZKPProtocol[] ors = new ZKPProtocol[] {baseProof, baseProof};
		
		
		//Prove each ciphertext is 0 or 1
		ZKPProtocol[] zkpArray = new ZKPProtocol[numCandidates+1];
		
		for(int i = 0; i < zkpArray.length; i++) {
			zkpArray[i] = baseProof;
		}
		

		ZKPProtocol[] orsCombined = new ZKPProtocol[numCandidates];
		for(int i = 0; i < orsCombined.length; i++) {
			orsCombined[i] = new ZeroKnowledgeOrProver(ors, order);
		}
		
		ZKPProtocol fullProof = new ZeroKnowledgeAndProver(new ZKPProtocol[] {new ZeroKnowledgeAndProver(orsCombined), new ZeroKnowledgeOrProver(zkpArray, order)});

		CryptoData env = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(environmentZeroOrOne), envCombined});
		CryptoData publicInputs = new CryptoDataArray(new CryptoData[] {new CryptoDataArray(publicInputsZeroOrOne), publicInputsCombined});
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
		AdditiveCiphertext[] zeroVote = new AdditiveCiphertext[numCandidates];
		for(int i = 0; i < zeroVote.length; i++) {
			zeroVote[i] = raceKey.getEmptyCiphertext();
		}
		return new SVHNwEncryptedVoteMulti(zeroVote, null);
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