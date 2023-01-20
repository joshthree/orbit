package test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

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
import election.singleCipherSVHNw.SVHNwRace;
import election.singleCipherSVHNw.SVHNwVoterDecision;
import transactions.BallotTransaction;
import transactions.ProcessedBlockchain;

public class Test2_1Multi {
	public static void main(String arg[]) {
		int numRaces = 5;
		int numCandidates = 4;
		int numVotes = 10;
		int numMiners = 10;
		int ringSize = 15;
		//SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
		SecureRandom rand = new SecureRandom();
		
		PaillierPrivKey priv = new PaillierPrivKey(2048, rand); 
//		System.out.println(priv);
		PaillierPubKey pub = (PaillierPubKey) priv.getPubKey();
		int bitSeparation = 33;
		
		electionTest(numRaces, numCandidates, numVotes, numMiners, ringSize, rand, pub, bitSeparation);
	}

	public static void electionTest(int numRaces, int numCandidates, int numVotes, int miners, int ringSize, SecureRandom rand,
			Additive_Pub_Key pub, int bitSeparation) {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

		ECCurve c = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = c.getOrder();
		Race[] races = new Race[numRaces];
		
		for (int i = 0; i < numRaces; i++) {
			races[i] = new SVHNwRaceMulti("", numCandidates, pub);
		}
		AdditiveElgamalPrivKey[] minerPrivKeys = new AdditiveElgamalPrivKey[miners];
		AdditiveElgamalPubKey minerKey = new AdditiveElgamalPubKey(g, c.getInfinity());
		
		for(int i = 0; i < minerPrivKeys.length; i++) {
			minerPrivKeys[i] = new AdditiveElgamalPrivKey(g, rand);
			minerKey = (AdditiveElgamalPubKey) minerKey.combineKeys(minerPrivKeys[i].getPubKey());
		}

		Election election = new Election(races, String.format("test election, numCandidates=%d, numRaces=%d", numCandidates, numRaces), minerKey, 8,4, 3);
		
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
		
//		for (int i = 0; i < numRaces; i++) {
//			for (int j = 0; j < numCandidates; j++) {
//				System.out.printf("%d, ", bdResults[i][j]);
//			}
//			System.out.println();
//		}
		ProcessedBlockchain blockchain = new ProcessedBlockchain();
		BallotTransaction[] ballots = Test2_1.createTransactions(election, encryptedVotes, blockchain, ringSize, rand);

		long start4 = System.currentTimeMillis();
		System.out.printf("%d, %d, %d, ", start1-start0, start2-start1, start3-start2, start4-start3);
//		ObjectInputStream[][] in = new ObjectInputStream[miners][miners];
//		ObjectOutputStream[][] out = new ObjectOutputStream[miners][miners];
//		Socket[][] s = new Socket[miners][miners];
//		int basePort = 5000;
//		AdditiveElgamalPubKey[] individualMinerKeys = new AdditiveElgamalPubKey[minerPrivKeys.length];
//		for(int i = 0; i < miners; i++) {
//			individualMinerKeys[i] = (AdditiveElgamalPubKey) minerPrivKeys[i].getPubKey();
//			for(int j = 0; j < miners; j++) {
//				if(i == j) continue;
//				try {
//					PipedInputStream pIn = new PipedInputStream(3000000);
//					PipedOutputStream pOut = new PipedOutputStream(pIn);
//					out[j][i] = new ObjectOutputStream(pOut);
//					in[i][j] = new ObjectInputStream(pIn);
//					
//				} catch (IOException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//			}
//		}
//		
//		
////		for(int i = 0; i < in.length; i++) {
////			for(int j = 0; j < in[i].length; j++) {
////				if(i == j) {
////					continue;
////				}
////				System.out.printf("Testing %d->%d\n", i, j);
////				try {
////					out[i][j].writeInt(4);
////					int x  = in[j][i].readInt();
////				} catch (IOException e) {
////					// TODO Auto-generated catch block
////					e.printStackTrace();
////				}
////				
////			}
////		}
//		
//		
//		Thread[] minerThread = new Thread[miners];
//		System.err.println("Test Writing Blockchain");
//		ByteArrayOutputStream out1 = new ByteArrayOutputStream();
//		try {
//			ObjectOutput out2 = new ObjectOutputStream(out1);
//			out2.writeObject(ballots);
//			System.out.println("Array size = " + out1.toByteArray().length);
//			ByteArrayInputStream in1 = new ByteArrayInputStream(out1.toByteArray());
//			ObjectInput in2 = new ObjectInputStream(in1);
//			in2.readObject();
//		} catch (IOException e) {
//			e.printStackTrace();
//		} catch (ClassNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		System.err.println("End Test Writing Blockchain");
//		for(int i = 0; i < miners; i++) {
//			try {
//				if(i == 0) {
//					
////					out[1][i].writeObject(minerKey);
//					out[1][i].writeObject(blockchain);
//					out[1][i].flush();
//					out[1][i].reset();
//					out[1][i].writeObject(ballots);
//					out[1][i].flush();
//					out[1][i].reset();
//				} else {
////					out[0][i].writeObject(minerKey);
//					out[0][i].writeObject(blockchain);
//					out[0][i].flush();
//					out[0][i].reset();
//					out[0][i].writeObject(ballots);
//					out[0][i].flush();
//					out[0][i].reset();
//				}
//			} catch (IOException e) {
//				e.printStackTrace();
//			}
//		}
//		for(int i = 0; i < miners; i++) {
//			minerThread[i] = new Thread(new MinerThread(minerPrivKeys[i], individualMinerKeys, in[i], out[i]));
//			minerThread[i].start();
//		}
//		for(int i = 0; i < miners; i++) {
//			try {
//				minerThread[i].join();
//			} catch (InterruptedException e) {
//				// TODO Auto-generated catch block
//				e.printStackTrace();
//			}
//		}
	}
}
