package test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import blah.AdditiveElgamalPrivKey;
import blah.AdditiveElgamalPubKey;
import transactions.BallotT;
import transactions.ProcessedBlockchain;
import zero_knowledge_proofs.ECPedersenCommitment;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class MinerThread implements Runnable {
	private BallotT[] votes;
	private ObjectOutputStream[] out;
	private ObjectInputStream[] in;
	private AdditiveElgamalPrivKey minerPrivKey;
	private SecureRandom rand = new SecureRandom();
	private boolean pass;
	private AdditiveElgamalPubKey[] individualMinerKeys;
	private ProcessedBlockchain blockchain;
	public long cpuTime;
	private boolean leader = false;
	
	public MinerThread(AdditiveElgamalPrivKey minerPrivKey, AdditiveElgamalPubKey[] individualMinerKeys, ObjectInputStream[] in, ObjectOutputStream[] out) {
		
		this.out = out;
		this.in = in;
		this.minerPrivKey = minerPrivKey;
		for(int i = 0; i < in.length; i++) {
			if(in[i] == null) {
				break;
			}
		}
		this.individualMinerKeys = individualMinerKeys;
		
		if(in.length != 1) {
			try {
				if(in[0] == null) {
					leader = true;
					blockchain = (ProcessedBlockchain) in[1].readObject();
					votes = (BallotT[]) in[1].readObject();
	//				AdditiveElgamalPubKey key = (AdditiveElgamalPubKey) in[1].readObject();
				} else {
					blockchain = (ProcessedBlockchain) in[0].readObject();
					votes = (BallotT[]) in[0].readObject();
	//				AdditiveElgamalPubKey key = (AdditiveElgamalPubKey) in[0].readObject();
				}
			} catch (ClassNotFoundException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			leader = true;

			try {
				blockchain = (ProcessedBlockchain) in[0].readObject();
				votes = (BallotT[]) in[0].readObject();
				in[0] = null;
				out[0] = null;
			} catch (ClassNotFoundException | IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		
		
	}
	
	@Override
	public void run() {
		ThreadMXBean threadTracker = ManagementFactory.getThreadMXBean();
		threadTracker.setThreadCpuTimeEnabled(true);
		
		
		long start = System.currentTimeMillis();
		for(int i = 0; i < votes.length; i++) {
			if(leader) System.out.print(i + " ");
			votes[i].minerProcessBallot(blockchain, minerPrivKey,individualMinerKeys, in, out, rand);
			blockchain.addTransaction(votes[i]);
		}
		
		cpuTime = threadTracker.getCurrentThreadCpuTime();
		
		if(leader) {
			System.out.printf(", $d, ", System.currentTimeMillis() - start); //ysstart2
			try {
				
				ByteArrayOutputStream out1 = new ByteArrayOutputStream();
				ObjectOutput out2 = new ObjectOutputStream(out1);
				out2.writeObject(votes);
				System.out.printf(out1.toByteArray().length+","); //ysafter3
				ByteArrayInputStream in1 = new ByteArrayInputStream(out1.toByteArray());
				ObjectInput in2 = new ObjectInputStream(in1);
				in2.readObject();
			} catch (IOException e) {
				e.printStackTrace();
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		
		}
		
		
		
	}
	public static int voteOnValue(int modulus, ObjectInputStream[] in, ObjectOutputStream[] out, AdditiveElgamalPubKey minerKey,
			SecureRandom rand) {
		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();
		ECPoint y = minerKey.getY();
		try {
			int firstPosVote = rand.nextInt(modulus);
			int firstPos = firstPosVote;
			CryptoData env = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(y)});
			BigInteger ped1R = minerKey.generateEphemeral(rand);
			ECPedersenCommitment ped = new ECPedersenCommitment(BigInteger.valueOf(firstPosVote), ped1R, env);
			for(int i = 0; i < out.length; i++) {
				if(out[i] == null) continue;
				out[i].writeObject(ped);
			}
			ECPedersenCommitment[] otherPeds = new ECPedersenCommitment[in.length];
			for(int i = 0; i < in.length; i++) {
				if(in[i] == null) continue;
				out[i].flush();
				otherPeds[i] = (ECPedersenCommitment) in[i].readObject();
			}
			for(int i = 0; i < out.length; i++) {
				if(out[i] == null) continue;
				out[i].writeObject(BigInteger.valueOf(firstPosVote));
				out[i].writeObject(ped1R);
			}
			for(int i = 0; i < in.length; i++) {
				if(in[i] == null) continue;
				out[i].flush();
				BigInteger otherPos = (BigInteger) in[i].readObject();
				BigInteger otherR = (BigInteger) in[i].readObject();
				if(!otherPeds[i].verifyCommitment(otherPos, otherR, env)) {
					System.out.println("Commitment 1 failed on " + i);
				}
				firstPos += otherPos.intValue();
			}
			firstPos = firstPos % in.length;
			return firstPos;
		}
		catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return -1;
		}
	}

	public static int[] chooseOrder(ObjectInputStream[] in, ObjectOutputStream[] out, AdditiveElgamalPubKey minerKey, SecureRandom rand) {
		if(in.length == 1) {
			return new int[] {0};
		}
		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();
		ECPoint y = minerKey.getY();
		try {
			int[] myVals = new int[in.length-1];
			
			for(int i = 0; i < myVals.length; i++) {
				myVals[i] = rand.nextInt(in.length + 1 - i) + i;
			}

			byte[] myValsBytes = new byte[myVals.length];

			for(int i = 0; i < myVals.length; i++) {
		        myValsBytes[i] = (byte)(myVals[i]);
		    }
			

			CryptoData env = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(y)});
			BigInteger ped1R = minerKey.generateEphemeral(rand);
			ECPedersenCommitment myPed = new ECPedersenCommitment(new BigInteger(myValsBytes), ped1R, env);
			
			for(int i = 0; i < out.length; i++) {
				if(out[i] == null) continue;
				out[i].writeObject(myPed);
			}
			ECPedersenCommitment[] otherPeds = new ECPedersenCommitment[in.length];
			for(int i = 0; i < in.length; i++) {
				if(in[i] == null) continue;
				out[i].flush();
				otherPeds[i] = (ECPedersenCommitment) in[i].readObject();
			}
			for(int i = 0; i < out.length; i++) {
				if(out[i] == null) continue;
				out[i].writeObject(myValsBytes);
				out[i].writeObject(ped1R);
			}
			for(int i = 0; i < in.length; i++) {
				if(in[i] == null) {
					continue;
				}
				out[i].flush();
				byte[] otherPos = (byte[]) in[i].readObject();
				BigInteger otherR = (BigInteger) in[i].readObject();
//				System.out.println(Thread.currentThread() + " Reading from " + i + " in order");
				if(!otherPeds[i].verifyCommitment(new BigInteger(1, otherPos), otherR, env)) {
					System.out.println("Commitment 1 failed on " + i);
				}
				
				for(int j = 0; j < myVals.length; j++) {
					myVals[j] += otherPos[j];			
				}	
			}
			int[] toReturn = new int[in.length];
			for(int j = 0; j < myVals.length; j++) {
				myVals[j] = myVals[j] % (in.length - j);			
				toReturn[j+1] = j+1;
			}	
			
			for(int j = 0; j < in.length-1; j++) {
				int temp = toReturn[j];
				toReturn[j] = toReturn[(in.length - 1) - myVals[j]];
				toReturn[(in.length - 1) - myVals[j]] = temp;
			}	

//			System.out.println(Thread.currentThread() + " order = " + Arrays.toString(toReturn));
			return toReturn;
			
		}
		catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
	
	public boolean success() {
		return pass;
	}
}
