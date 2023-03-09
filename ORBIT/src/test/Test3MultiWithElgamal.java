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
import election.EncryptedVote;
import zero_knowledge_proofs.ZKToolkit;

public class Test3MultiWithElgamal {
	public static void main(String arg[]) {
		ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
		int numRaces = 5;
		int numCandidates = 4;
		int numVotes = 10;
		int miners = 10;
		int ringSize = 5;
		
		ECCurve c = spec.getCurve();
		ECPoint g = spec.getG();
		
		
//		ECPoint p = g.multiply(BigInteger.valueOf(1000000));
//		
//		long time1 = System.currentTimeMillis();
//		while(!p.equals(c.getInfinity()))
//		{
//			p = p.subtract(g);
//		}
		long time2 = System.currentTimeMillis();
//		System.out.println(time2-time1);
		BigInteger order = c.getOrder();
		
		SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
//		SecureRandom rand = new SecureRandom();
		
		BigInteger x = ZKToolkit.random(order, rand);
		
		
		Additive_Priv_Key priv = new AdditiveElgamalPrivKey(g, rand); 
//		System.out.println(priv);
		Additive_Pub_Key pub = priv.getPubKey();
		int bitSeparation = 33;
		
		Test3Multi.electionTest(numRaces, numCandidates, numVotes, miners, ringSize, rand, pub, bitSeparation);
		
	}
}
