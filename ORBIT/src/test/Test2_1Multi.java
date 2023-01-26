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

		Test2_1.runElection(numRaces, numCandidates, numVotes, miners, ringSize, rand, c, g, races);
	}
}
