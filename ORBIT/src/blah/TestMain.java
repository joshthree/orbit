package blah;

import java.math.BigInteger;
import java.security.SecureRandom;

public class TestMain {

	public static void main(String[] args) {
		SecureRandom rand = new SecureRandom();
		Additive_Priv_Key priv = new PaillierPrivKey(2048, rand);
		Additive_Priv_Key priv2 = new PaillierPrivKey(2048, rand);
		Additive_Pub_Key pub = priv.getPubKey();
		PaillierPubKey blah = ((PaillierPubKey) pub);
		System.out.println(blah.getN());
		AdditiveCiphertext[] c = new AdditiveCiphertext[7];

		c[0] = pub.encrypt(BigInteger.valueOf(1), rand);
		c[1] = pub.encrypt(BigInteger.valueOf(20), rand);
		c[2] = pub.encrypt(BigInteger.valueOf(300), rand);
		c[3] = pub.encrypt(BigInteger.valueOf(4000), rand);
		c[4] = pub.encrypt(BigInteger.valueOf(50000), rand);
		c[5] = pub.encrypt(BigInteger.valueOf(600000), rand);
		c[6] = pub.encrypt(BigInteger.valueOf(7000000), rand);
		AdditiveCiphertext c1 = pub.encrypt(BigInteger.valueOf(6), rand);
		AdditiveCiphertext c2 = pub.encrypt(BigInteger.valueOf(900), rand);

		AdditiveCiphertext c3 = c1.homomorphicAdd(c2);
		System.out.println(priv.decrypt(c1).getValue());
		System.out.println(priv.decrypt(c2).getValue());
		System.out.println(priv.decrypt(c3).getValue());
		
		AdditiveCiphertext c4 = AdditiveCiphertext.homomorphicSum(c);
		

		for(int i = 0; i < c.length; i++) {
			System.out.println(priv.decrypt(c[i]).getValue());
		}
		System.out.println("hi");
		System.out.println(priv.decrypt(c4).getValue());
		
		AdditiveCiphertext c5 = c1.scalarMultiply(BigInteger.valueOf(10000));

		System.out.println(priv.decrypt(c1).getValue());
		System.out.println(priv.decrypt(c5).getValue());
		
		System.out.println(c1);
		AdditiveCiphertext c1r = (AdditiveCiphertext) c1.rerandomize(rand);
		System.out.println(c1r);
		System.out.println(priv.decrypt(c1r).getValue());
	}

}
