package test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import blah.AdditiveElgamalPrivKey;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;

public class Test3WithElgamal {
	public static void main(String arg[]) {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		int numRaces = 5;
		int numCandidates = 4;
		int numVotes = 2;
		int ringSize = 15;
		int miners = 10;

		ECCurve c = spec.getCurve();
		ECPoint g = spec.getG();
		BigInteger order = c.getOrder();
		//SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
		SecureRandom rand = new SecureRandom();
		
		Additive_Priv_Key priv = new AdditiveElgamalPrivKey(g, rand); 
//		System.out.println(priv);
		Additive_Pub_Key pub = priv.getPubKey();
		int bitSeparation = 33;
		
		Test3.electionTest(numRaces, numCandidates, numVotes, miners, ringSize, rand, pub, bitSeparation);
	}
}
