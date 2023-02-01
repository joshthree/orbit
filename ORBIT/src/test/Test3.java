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
import transactions.BallotTransaction1;
import transactions.BallotTransaction2;
import transactions.BallotTransaction3;
import transactions.ElectionTransaction;
import transactions.ProcessedBlockchain;
import transactions.RegistrationTransaction;
import transactions.SourceTransaction;

public class Test3 {
	public static void main2(String arg[]) {
		int numRaces = 5;
		int numCandidates = 4;
		int numVotes = 20;
		int miners = 15;
		int ringSize = 15;
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
			races[i] = new SVHNwRace("", numCandidates, pub, bitSeparation);
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
		
//		if (verified) {
//			System.out.println("All good");
//		}
		
		long start3 = System.currentTimeMillis();
		
//		for (int i = 0; i < numRaces; i++) {
//			for (int j = 0; j < numCandidates; j++) {
//				System.out.printf("%d, ", bdResults[i][j]);
//			}
//			System.out.println();
//		}

		ProcessedBlockchain blockchain = new ProcessedBlockchain();
		BallotT[] ballots = Test3.createTransactions(election, encryptedVotes, blockchain, ringSize, rand);

		long start4 = System.currentTimeMillis();
		System.out.printf("%d, %d, %d, %d \n", start1-start0, start2-start1, start3-start2, start4-start3);
		ObjectInputStream[][] in = new ObjectInputStream[miners][miners];
		ObjectOutputStream[][] out = new ObjectOutputStream[miners][miners];
		AdditiveElgamalPubKey[] individualMinerKeys = new AdditiveElgamalPubKey[minerPrivKeys.length];
		for(int i = 0; i < miners; i++) {
			individualMinerKeys[i] = (AdditiveElgamalPubKey) minerPrivKeys[i].getPubKey();
			for(int j = 0; j < miners; j++) {
				if(i == j) continue;
				try {
					PipedInputStream pIn = new PipedInputStream(3000000);
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
		System.err.println("Test Writing Blockchain");
		ByteArrayOutputStream out1 = new ByteArrayOutputStream();
		try {
			ObjectOutput out2 = new ObjectOutputStream(out1);
			out2.writeObject(ballots);
			System.out.println("Array size = " + out1.toByteArray().length);
			ByteArrayInputStream in1 = new ByteArrayInputStream(out1.toByteArray());
			ObjectInput in2 = new ObjectInputStream(in1);
			in2.readObject();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.err.println("End Test Writing Blockchain");
		for(int i = 0; i < miners; i++) {
			try {
				if(i == 0) {
					
//					out[1][i].writeObject(minerKey);
					out[1][i].writeObject(blockchain);
					out[1][i].flush();
					out[1][i].reset();
					out[1][i].writeObject(ballots);
					out[1][i].flush();
					out[1][i].reset();
				} else {
//					out[0][i].writeObject(minerKey);
					out[0][i].writeObject(blockchain);
					out[0][i].flush();
					out[0][i].reset();
					out[0][i].writeObject(ballots);
					out[0][i].flush();
					out[0][i].reset();
				}
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		for(int i = 0; i < miners; i++) {
			minerThread[i] = new Thread(new MinerThread(minerPrivKeys[i], individualMinerKeys, in[i], out[i]));
			minerThread[i].start();
		}
		for(int i = 0; i < miners; i++) {
			try {
				minerThread[i].join();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	public static BallotT[] createTransactions(Election election, EncryptedVote[][] encryptedVotes, ProcessedBlockchain blockchain, int ringSize, SecureRandom rand) {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		ECCurve curve = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = curve.getOrder();

		AdditiveElgamalPrivKey[][] voterPriv = new AdditiveElgamalPrivKey[encryptedVotes.length][2];
		BigInteger[][] passwords = new BigInteger[encryptedVotes.length][3];
		AdditiveElgamalCiphertext[] passwordCiphers = new AdditiveElgamalCiphertext[encryptedVotes.length];
		
		RegistrationTransaction[] registration = new RegistrationTransaction[encryptedVotes.length];
		
		ElectionTransaction electionTx = new ElectionTransaction(election);
		blockchain.addTransaction(electionTx);
		System.out.println(electionTx.getPosition());
		for(int i = 0; i < encryptedVotes.length; i++) {
			voterPriv[i][0] = new AdditiveElgamalPrivKey(g, rand);
			voterPriv[i][1] = new AdditiveElgamalPrivKey(g, rand);

			passwords[i][0] = election.getMinerKey().generateEphemeral(rand);
			do {
				passwords[i][1] = election.getMinerKey().generateEphemeral(rand);
				
			} while(passwords[i][1].equals(BigInteger.ZERO));
			passwords[i][2] = election.getMinerKey().generateEphemeral(rand);
			
			passwordCiphers[i] = (AdditiveElgamalCiphertext) election.getMinerKey().combineKeys(voterPriv[i][0].getPubKey()).encrypt(passwords[i][0], rand);
			registration[i] = new RegistrationTransaction((AdditiveElgamalPubKey) voterPriv[i][0].getPubKey(), passwordCiphers[i], rand);
			blockchain.addTransaction(registration[i]);
		}



		
		
		BallotT[] ballots = new BallotT[encryptedVotes.length+1];

		long time3 = System.currentTimeMillis();
		for(int i = 0; i < encryptedVotes.length; i++) {
			int sourcePos = rand.nextInt(ringSize);
			SourceTransaction[] ring = new SourceTransaction[ringSize];
			ring[sourcePos] = registration[i];
			ArrayList<Integer> ringMembers = new ArrayList<Integer>();
			ringMembers.add(i);
			for(int j = 0; j < ringSize; j++) {
				if(j == sourcePos) continue;
				Integer mixin;
				do {
					mixin = rand.nextInt(registration.length);
				} while(ringMembers.contains(mixin));
				
				ringMembers.add(mixin);
				ring[j] = registration[mixin];
				
			}
			ballots[i] = new BallotTransaction3(ring, sourcePos, voterPriv[i][0], voterPriv[i][1], passwords[i][0], passwords[i][1], electionTx, encryptedVotes[i], passwords[i][2], rand);
		}
		int last = encryptedVotes.length;
		int sourcePos = rand.nextInt(ringSize);
		SourceTransaction[] ring = new SourceTransaction[ringSize];
		ring[sourcePos] = registration[0];
		ArrayList<Integer> ringMembers = new ArrayList<Integer>();
		ringMembers.add(0);
		for(int j = 0; j < ringSize; j++) {
			if(j == sourcePos) continue;
			Integer mixin;
			do {
				mixin = rand.nextInt(registration.length);
			} while(ringMembers.contains(mixin));
			
			ringMembers.add(mixin);
			ring[j] = registration[mixin];
			
		}
		ballots[last] = new BallotTransaction3(ring, sourcePos, voterPriv[0][0], new AdditiveElgamalPrivKey(g, rand), passwords[0][0].add(BigInteger.ONE), passwords[0][1], electionTx, encryptedVotes[0], passwords[0][2], rand);

		BallotT[] ballots2 = new BallotT[encryptedVotes.length+1];
		for(int i = 0; i < ballots2.length; i++) {
			ballots2[(i+1)%ballots2.length] = ballots[i];
		}
		
		
		
		long time4 = System.currentTimeMillis();
		System.out.println(time4 - time3);
		for(int i = 0; i < ballots2.length; i++) {
			if(!ballots2[i].verifyTransaction(blockchain))
			{
				System.out.println("NOOOOO");
			}
		}


		long time5 = System.currentTimeMillis();
		System.out.println(time5 - time4);
		return ballots2;
	}
}
