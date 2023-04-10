package test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
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
import election.singleCipherSVHNw.SVHNwRace;
import election.singleCipherSVHNw.SVHNwVoterDecision;
import transactions.BallotT;
import transactions.ProcessedBlockchain;

public class Test3Multi {
	public static void main(String arg[]) {
		int numRaces = Integer.parseInt(arg[0]);
		int numCandidates = Integer.parseInt(arg[1]);
		int numVotes = Integer.parseInt(arg[2]);
		int miners = Integer.parseInt(arg[3]); //ys numMiners vs miners
		int ringSize = Integer.parseInt(arg[4]);
		//SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
		SecureRandom rand = new SecureRandom();
		
		PaillierPrivKey priv = new PaillierPrivKey(2048, rand);
		System.out.println(priv);
		PaillierPubKey pub = (PaillierPubKey) priv.getPubKey();
		int bitSeparation = 33;
		
		electionTest(numRaces, numCandidates, numVotes, miners, ringSize, rand, pub, bitSeparation);
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

		Election election = new Election(races, String.format("test election, numCandidates=%d, numRaces=%d", numCandidates, numRaces), minerKey, 16,8, 5);
		
		int[][] bdResults = new int[numRaces][numCandidates+1];
		
		EncryptedVote[][] encryptedVotes = new EncryptedVote[numVotes][];
		
		long start0 = System.currentTimeMillis();
		
		VoterDecision[][] voterDecisions = new VoterDecision[numVotes][numRaces];
		for (int i = 0; i < numVotes; i++) {
			//Create VoterDecision array
			
			
			for (int j = 0; j < numRaces; j++) {
				//Fill the array with random votes
				int vote = rand.nextInt(numCandidates+1);
				voterDecisions[i][j] = new SVHNwVoterDecision(vote);
				
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
			//ysSystem.out.println("All good");
		}
		
		long start3 = System.currentTimeMillis();
		
		for (int i = 0; i < numRaces; i++) {
			for (int j = 0; j < numCandidates; j++) {
				//System.out.printf("%d, ", bdResults[i][j]); ys
			}
			//System.out.println(); ys
		}

		//ysSystem.out.printf("%d, %d, %d, ", start1-start0, start2-start1, start3-start2);
		ProcessedBlockchain blockchain = new ProcessedBlockchain();
		Test3.createTransactions(election, encryptedVotes, blockchain, ringSize, rand);
		
		
		
		int numBallots = encryptedVotes.length;
		ObjectInputStream[][] in = new ObjectInputStream[miners][miners];
		ObjectOutputStream[][] out = new ObjectOutputStream[miners][miners];
		Socket[][] s = new Socket[miners][miners];
		int basePort = 5000;
		AdditiveElgamalPubKey[] individualMinerKeys = new AdditiveElgamalPubKey[minerPrivKeys.length];
		for(int i = 0; i < miners; i++) {
			individualMinerKeys[i] = (AdditiveElgamalPubKey) minerPrivKeys[i].getPubKey();
			for(int j = 0; j < miners; j++) {
				if(i == j) continue;
				try {
					PipedInputStream pIn = new PipedInputStream(400000);
					PipedOutputStream pOut = new PipedOutputStream(pIn);
					out[j][i] = new ObjectOutputStream(pOut);
					in[i][j] = new ObjectInputStream(pIn);
					
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		
//		for(int i = 0; i < in.length; i++) {
//			for(int j = 0; j < in[i].length; j++) {
//				if(i == j) {
//					continue;
//				}
//				System.out.printf("Testing %d->%d\n", i, j);
//				try {
//					out[i][j].writeInt(4);
//					int x  = in[j][i].readInt();
//				} catch (IOException e) {
//					// TODO Auto-generated catch block
//					e.printStackTrace();
//				}
//				
//			}
//		}
		
		
		Thread[] minerThread = new Thread[miners];
		//ysSystem.err.println("Test Writing Blockchain");
		//ysSystem.err.println("End Test Writing Blockchain");
		
		MinerThread[] minerThreadDriver = new MinerThread[miners];
		for(int i = 0; i < miners; i++) {
			minerThreadDriver[i] = new MinerThread(minerPrivKeys[i], individualMinerKeys, in[i], out[i]);
			minerThread[i] = new Thread(minerThreadDriver[i]);
			minerThread[i].start();
		}
		long cpuTime = 0;
		
		if(miners != 1) {
			for(int i = 0; i < miners; i++) {
				try {
					if(i == 0) {
						
	//					out[1][i].writeObject(minerKey);
						out[1][i].writeInt(numBallots);
						out[1][i].flush();
						out[1][i].writeObject(blockchain);
						out[1][i].flush();
						out[1][i].reset();
					} else {
	//					out[0][i].writeObject(minerKey);
						out[0][i].writeInt(numBallots);
						out[0][i].flush();
						out[0][i].writeObject(blockchain);
						out[0][i].flush();
						out[0][i].reset();
					}
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			
			for(int i = 0; i < miners; i++) {
				if(i == 0) {
					try {
						out[1][0].writeBoolean(true);
						out[1][0].flush();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
				else {
					try {
						out[0][i].writeBoolean(true);
						out[0][i].flush();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					
				}
			}
		} else {
			try {
				PipedInputStream pIn = new PipedInputStream(4000000);
				PipedOutputStream pOut = new PipedOutputStream(pIn);
				out[0][0] = new ObjectOutputStream(pOut);
				in[0][0] = new ObjectInputStream(pIn);
				out[0][0].writeInt(numBallots);
				out[0][0].writeObject(blockchain);
				out[0][0].flush();
				out[0][0].reset();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		for(int i = 0; i < miners; i++) {
			try {
				minerThread[i].join();
				cpuTime += minerThreadDriver[i].cpuTime;
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		for(int i = 0; i < miners; i++) {
			for(int j = 0; j < miners; j++) {
				if(i == j) continue;
				try {
					in[i][j].close();
					out[i][j].close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		System.out.println(cpuTime); //ysend4 total CPU time it took ALL miner to process all BALLOTS
	}
}
