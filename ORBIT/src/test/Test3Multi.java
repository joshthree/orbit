package test;

import java.security.SecureRandom;

import blah.AdditiveElgamalPrivKey;
import blah.AdditiveElgamalPubKey;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;
import blah.PaillierPrivKey;
import blah.PaillierPubKey;
import election.Election;
import election.EncryptedVote;
import election.Race;
import election.VoterDecision;
import election.multiCipherSVHNw.SVHNwRaceMulti;
import election.multiCipherSVHNw.SVHNwVoterDecisionMulti;

public class Test3Multi {
	public static void main(String arg[]) {
		int numRaces = 5;
		int numCandidates = 4;
		int numVotes = 50;
		
		//SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
		SecureRandom rand = new SecureRandom();
		
		PaillierPrivKey priv = new PaillierPrivKey(2048, rand); 
		System.out.println(priv);
		PaillierPubKey pub = (PaillierPubKey) priv.getPubKey();
		int bitSeparation = 33;
		
		electionTest(numRaces, numCandidates, numVotes, rand, pub, bitSeparation);
	}

	public static void electionTest(int numRaces, int numCandidates, int numVotes, SecureRandom rand,
			Additive_Pub_Key pub, int bitSeparation) {
		Race[] races = new Race[numRaces];
		
		for (int i = 0; i < numRaces; i++) {
			races[i] = new SVHNwRaceMulti("", numCandidates, pub);
		}
		AdditiveElgamalPubKey minerKey = null;
		Election election = new Election(races, String.format("test election, numCandidates=%d, numRaces=%d", numCandidates, numRaces), minerKey);
		
		int[][] bdResults = new int[numRaces][numCandidates+1];
		
		EncryptedVote[][] encryptedVotes = new EncryptedVote[numVotes][];
		
		long start0 = System.currentTimeMillis();
		
		for (int i = 0; i < numVotes; i++) {
			//Create VoterDecision array
			
			VoterDecision[] voterDecisions = new VoterDecision[numRaces];
			
			for (int j = 0; j < numRaces; j++) {
				//Fill the array with random votes
				int vote = rand.nextInt(numCandidates+1);
				voterDecisions[j] = new SVHNwVoterDecisionMulti(vote);
				
				//Update bdResults//Update bdResults
				bdResults[j][vote]++; 
				
				
				
			}
			//Run vote function with the array.
			encryptedVotes[i] = election.vote(voterDecisions, rand);
		}
		
		long start1 = System.currentTimeMillis();
		
		
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
		
		long start2 = System.currentTimeMillis();
		
		for (int i = 0; i < numRaces; i++) {
			for (int j = 0; j < numCandidates; j++) {
				System.out.printf("%d, ", bdResults[i][j]);
			}
			System.out.println();
		}
	}
}
