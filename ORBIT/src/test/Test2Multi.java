package test;

import java.security.SecureRandom;

import blah.AdditiveElgamalPubKey;
import blah.Additive_Pub_Key;
import blah.PaillierPrivKey;
import blah.PaillierPubKey;
import election.Election;
import election.EncryptedVote;
import election.Race;
import election.VoterDecision;
import election.multiCipherSVHNw.SVHNwRaceMulti;
import election.multiCipherSVHNw.SVHNwVoterDecisionMulti;
import election.singleCipherSVHNw.SVHNwVoterDecision;

public class Test2Multi {
	public static void main(String arg[]) {
		int numRaces = 5;
		int numCandidates = 4;
		int numVotes = 10;
		
		//SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
		SecureRandom rand = new SecureRandom();
		
		PaillierPrivKey priv = new PaillierPrivKey(2048, rand); 
		System.out.println(priv);
		PaillierPubKey pub = (PaillierPubKey) priv.getPubKey();
		int bitSeparation = 33;
		
		electionTest(numRaces, numCandidates, numVotes, rand, pub, bitSeparation);
	}

	public static EncryptedVote[][] electionTest(int numRaces, int numCandidates, int numVotes, SecureRandom rand,
			Additive_Pub_Key pub, int bitSeparation) {
		Race[] races = new Race[numRaces];
		
		for (int i = 0; i < numRaces; i++) {
			races[i] = new SVHNwRaceMulti("", numCandidates, pub);
		}
		AdditiveElgamalPubKey minerKey = null;
		Election election = new Election(races, String.format("test election, numCandidates=%d, numRaces=%d", numCandidates, numRaces), minerKey, 8, 4, 3);
		
		int[][] bdResults = new int[numRaces][numCandidates+1];
		
		EncryptedVote[][] encryptedVotes = new EncryptedVote[numVotes][];
		
		long start0 = System.currentTimeMillis();
		VoterDecision[][] voterDecisions = new VoterDecision[numVotes][numRaces];
		for (int i = 0; i < numVotes; i++) {
			//Create VoterDecision array
			
			
			for (int j = 0; j < numRaces; j++) {
				//Fill the array with random votes
				int vote = rand.nextInt(numCandidates+1);
				voterDecisions[i][j] = new SVHNwVoterDecisionMulti(vote);
				
				//Update bdResults//Update bdResults
				bdResults[j][vote]++; 
				
				
				
			}
			//Run vote function with the array.
			encryptedVotes[i] = election.vote(voterDecisions[i], rand);
		}
		
		long start1 = System.currentTimeMillis();
		for (int i = 0; i < numVotes; i++) {
			encryptedVotes[i] = election.proveVote(encryptedVotes[i], voterDecisions[i], rand);
		}
		long start2 = System.currentTimeMillis();
		
		boolean verified = true;
		
		for (int i = 0; i < numVotes; i++) {
			if (!election.verify(encryptedVotes[i])) {
				verified = false;
				System.out.printf("race %d failed\n", i);
			}
			
		}
		
		
		if (verified) {
			System.out.println("All good");
		}
		
		long start3 = System.currentTimeMillis();
		
		for (int i = 0; i < numRaces; i++) {
			for (int j = 0; j < numCandidates; j++) {
				System.out.printf("%d, ", bdResults[i][j]);
			}
			System.out.println();
		}

		System.out.printf("%d, %d, %d, ", start1-start0, start2-start1, start3-start2);
		return encryptedVotes;
	}
}
