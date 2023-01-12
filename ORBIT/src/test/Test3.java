package test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import blah.AdditiveElgamalPrivKey;
import blah.AdditiveElgamalPubKey;
import blah.Additive_Pub_Key;
import blah.PaillierPrivKey;
import blah.PaillierPubKey;
import election.Election;
import election.EncryptedVote;
import election.Race;
import election.VoterDecision;
import election.singleCipherSVHNw.SVHNwRace;
import election.singleCipherSVHNw.SVHNwVoterDecision;
import transactions.ProcessedBlockchain;

public class Test3 {
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
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

		ECCurve c = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = c.getOrder();
		Race[] races = new Race[numRaces];
		
		for (int i = 0; i < numRaces; i++) {
			races[i] = new SVHNwRace("", numCandidates, pub, bitSeparation);
		}
		
		AdditiveElgamalPrivKey minerPrivKey = new AdditiveElgamalPrivKey(g, rand);
		AdditiveElgamalPubKey minerKey = (AdditiveElgamalPubKey) minerPrivKey.getPubKey();
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
				voterDecisions[j] = new SVHNwVoterDecision(vote);
				
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
		
		System.out.println(start1-start0);
		System.out.println(start2-start1);
	}
	public static void createTransactions(Election election, EncryptedVote[][] encryptedVotes, SecureRandom rand) {

		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		ProcessedBlockchain blockchain = new ProcessedBlockchain();
		ECCurve c = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = c.getOrder();

		AdditiveElgamalPrivKey[][] voterPriv = new AdditiveElgamalPrivKey[encryptedVotes.length][2];
		BigInteger[][] passwords = new BigInteger[encryptedVotes.length][2];
		for(int i = 0; i < encryptedVotes.length; i++) {
			voterPriv[i][0] = new AdditiveElgamalPrivKey(g, rand);
			voterPriv[i][1] = new AdditiveElgamalPrivKey(g, rand);
			
			
		}
	}
}
