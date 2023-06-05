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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import blah.AdditiveElgamalCiphertext;
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
import transactions.BallotT;
import transactions.BallotTransaction;
import transactions.BallotTransaction6;
import transactions.ElectionTransaction;
import transactions.ProcessedBlockchain;
import transactions.RegistrationTransaction;
import transactions.SourceTransaction;
import transactions.SpoilTransaction;

public class Test2_1 {
	public static void main2(String arg[]) {
		int numRaces = Integer.parseInt(arg[0]);
		int numCandidates = Integer.parseInt(arg[1]);
		int numVotes = Integer.parseInt(arg[2]);
		int miners = Integer.parseInt(arg[3]);
		int ringSize = Integer.parseInt(arg[4]);
		//SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
		SecureRandom rand = new SecureRandom();
		
		PaillierPrivKey priv = new PaillierPrivKey(2048, rand); 
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
			races[i] = new SVHNwRace("sfgsdf", numCandidates, pub, bitSeparation);
		}
		runElection(numRaces, numCandidates, numVotes, miners, ringSize, rand, c, g, races);
	}

	public static void runElection(int numRaces, int numCandidates, int numVotes, int miners, int ringSize,
			SecureRandom rand, ECCurve c, ECPoint g, Race[] races) {
		AdditiveElgamalPrivKey[] minerPrivKeys = new AdditiveElgamalPrivKey[miners];
		AdditiveElgamalPubKey minerKey = new AdditiveElgamalPubKey(g, c.getInfinity());
		
		for(int i = 0; i < minerPrivKeys.length; i++) {
			minerPrivKeys[i] = new AdditiveElgamalPrivKey(g, rand);
			minerKey = (AdditiveElgamalPubKey) minerKey.combineKeys(minerPrivKeys[i].getPubKey());
		}

		Election election = new Election(races, String.format("test election, numCandidates=%d, numRaces=%d", numCandidates, numRaces), minerKey, 8,4, 3);
		
		int[][] bdResults = new int[numRaces][numCandidates+1];
		
		EncryptedVote[][] encryptedVotes = new EncryptedVote[numVotes][];
		
		long start0 = System.nanoTime();
		
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
		
		long end0 = System.nanoTime();
		ByteArrayOutputStream out1 = new ByteArrayOutputStream();
		try {
			ObjectOutput out2 = new ObjectOutputStream(out1);
			out2.writeObject(encryptedVotes);
			System.out.printf("%d, ", out1.toByteArray().length);  //print1. Initial Votes size (pre-transaction, pre-proof)
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		long start1 = System.nanoTime();

		for (int i = 0; i < numVotes; i++) {
			encryptedVotes[i] = election.proveVote(encryptedVotes[i], voterDecisions[i], rand);
		}
		
		long end1 = System.nanoTime();
		
		out1 = new ByteArrayOutputStream();
		try {
			ObjectOutput out2 = new ObjectOutputStream(out1);
			out2.writeObject(encryptedVotes);
			System.out.printf("%d, ", out1.toByteArray().length); //print2. Initial Votes size (pre-transaction, with proof)
		} catch (IOException e) {
			e.printStackTrace();
		}
		

		long start2 = System.nanoTime();
		boolean verified = true;
		
		for (int i = 0; i < numVotes; i++) {
			if (!election.verify(encryptedVotes[i])) {
				verified = false;
				System.out.printf("race %d failed\n", i);
			}
			
		}
		
//		if (verified) {
//			System.out.println("All good");
//		}
		
		long end2 = System.nanoTime();
		
//		for (int i = 0; i < numRaces; i++) {
//			for (int j = 0; j < numCandidates; j++) {
//				System.out.printf("%d, ", bdResults[i][j]);
//			}
//			System.out.println();
//		}
		System.out.printf("%d, %d, %d, ", end0-start0, end1-start1, end2-start2);  //print3. time to vote, print4. time to prove votes, print5. time to verify voterVotes. 
		ProcessedBlockchain blockchain = new ProcessedBlockchain();
		long start3 = System.nanoTime();
		BallotT[] ballots = Test2_1.createTransactions(election, encryptedVotes, blockchain, ringSize, rand);
		long end3 = System.nanoTime();

		
		out1 = new ByteArrayOutputStream();
		try {
			ObjectOutput out2 = new ObjectOutputStream(out1);
			out2.writeObject(ballots);
			System.out.printf("%d, ", out1.toByteArray().length);  // print8. Size of ballots,
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		System.out.printf("%d \n", end3-start3);  //print9. time to create transactions,
		
		
		
//		ObjectInputStream[][] in = new ObjectInputStream[miners][miners];
//		ObjectOutputStream[][] out = new ObjectOutputStream[miners][miners];
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
	public static BallotT[] createTransactions(Election election, EncryptedVote[][] encryptedVotes, ProcessedBlockchain blockchain, int ringSize, SecureRandom rand) {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		ECCurve curve = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = curve.getOrder();

		int passwordNum = 5;
		int numReg = Math.max(encryptedVotes.length, ringSize);
		AdditiveElgamalPrivKey[][] voterPriv = new AdditiveElgamalPrivKey[numReg][2];
		BigInteger[][][] passwords = new BigInteger[numReg][3][];
		AdditiveElgamalCiphertext[][] passwordCiphers = new AdditiveElgamalCiphertext[numReg][5];
		
		SourceTransaction[] registration = new SourceTransaction[numReg];
		
		ElectionTransaction electionTx = new ElectionTransaction(election);
		blockchain.addTransaction(electionTx);
		AdditiveElgamalPubKey minerKey = election.getMinerKey();
		for(int i = 0; i < encryptedVotes.length || i < ringSize; i++) {
			voterPriv[i][0] = new AdditiveElgamalPrivKey(g, rand);
			voterPriv[i][1] = new AdditiveElgamalPrivKey(g, rand);

			passwords[i][0] = new BigInteger[passwordNum];
			passwords[i][1] = new BigInteger[1];
			passwords[i][2] = new BigInteger[1];
			
			for (int j = 0; j < passwordNum; j++) {
				passwords[i][0][j] = election.getMinerKey().generateEphemeral(rand);
				passwordCiphers[i][j] = (AdditiveElgamalCiphertext) election.getMinerKey().combineKeys(voterPriv[i][0].getPubKey()).encrypt(passwords[i][0][j], rand);
			}
			do {
				passwords[i][1][0] = election.getMinerKey().generateEphemeral(rand);
				
			} while(passwords[i][1][0].equals(BigInteger.ZERO));
			passwords[i][2][0] = election.getMinerKey().generateEphemeral(rand);
			if(i%2 == 0) {
				if(i%4 == 0) {
					registration[i] = new SpoilTransaction(voterPriv[i][0], passwordCiphers[i], minerKey.encrypt(BigInteger.ZERO, rand), null, rand);
				}
				else {
					registration[i] = new RegistrationTransaction((AdditiveElgamalPubKey) voterPriv[i][0].getPubKey(), passwordCiphers[i], rand);
				}
			} else {
				registration[i] = new SpoilTransaction(voterPriv[i][0], passwordCiphers[i], minerKey.encrypt(BigInteger.ONE, rand), null, rand);
			}
			blockchain.addTransaction(registration[i]);
		}
		


		
		
		BallotT[] ballots = new BallotT[encryptedVotes.length];

		long time3 = System.nanoTime();
		HashMap<Integer, Boolean> map = new HashMap<Integer, Boolean>();
		for(int i = 0; i < encryptedVotes.length; i++) {
			int sourcePos = rand.nextInt(ringSize);
			SourceTransaction[] ring = new SourceTransaction[ringSize];
			ring[sourcePos] = registration[i];
			map.put(i, true);
			for(int j = 0; j < ringSize; j++) {
				if(j == sourcePos) continue;
				Integer mixin;
				do {
					mixin = rand.nextInt(registration.length);
				} while(map.containsKey(mixin));
				map.put(mixin, true);
				ring[j] = registration[mixin];
			}
			map.clear();
			if((i%4/2) == 0) {
				ballots[i] = new BallotTransaction6(ring, sourcePos, voterPriv[i][0], voterPriv[i][1], passwords[i][0][0], passwords[i][1][0], electionTx, encryptedVotes[i], passwords[i][2][0], rand);
			} else {
				ballots[i] = new BallotTransaction6(ring, sourcePos, voterPriv[i][0], voterPriv[i][1], minerKey.generateEphemeral(rand), passwords[i][1][0], electionTx, encryptedVotes[i], passwords[i][2][0], rand);
			}
		}
//		int last = encryptedVotes.length;
//		int sourcePos = rand.nextInt(ringSize);
//		SourceTransaction[] ring = new SourceTransaction[ringSize];
//		ring[sourcePos] = registration[0];
//		ArrayList<Integer> ringMembers = new ArrayList<Integer>();
//		ringMembers.add(0);
//		for(int j = 0; j < ringSize; j++) {
//			if(j == sourcePos) continue;
//			Integer mixin;
//			do {
//				mixin = rand.nextInt(registration.length);
//			} while(ringMembers.contains(mixin));
//			
//			ringMembers.add(mixin);
//			ring[j] = registration[mixin];
//			
//		}
		

		
		long time4 = System.nanoTime();
		for(int i = 0; i < ballots.length; i++) {
			if(!ballots[i].verifyTransaction(blockchain))
			{
				System.out.println("NOOOOO");
			}
		}


		long time5 = System.nanoTime();
		System.out.printf("%d, %d, ", time4 - time3, time5 - time4);  //print6. Time to create ballot transaction, print7. time to verify ballot transaction (including verifying voterVotes again).
		return ballots;
	}
}
