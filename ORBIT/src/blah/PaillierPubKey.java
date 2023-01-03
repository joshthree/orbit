package blah;

import java.math.BigInteger;
import java.util.Random;

import zero_knowledge_proofs.PaillierProofOfZero;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class PaillierPubKey implements Additive_Pub_Key{

	/**
	 * 
	 */
	private static final long serialVersionUID = 7359364865124592286L;
	private BigInteger n;
	transient private BigInteger n2;
	private BigInteger g;
	
	
	protected PaillierPubKey(BigInteger n, BigInteger n2, BigInteger g) {
		System.out.println("in key, n = " + n);
		this.n = n;
		this.n2 = n2;
		this.g = g;
	}
	public PaillierPubKey(PaillierPubKey pubKey) {
		this.n = pubKey.n;
		this.n2 = pubKey.n2;
		this.g = pubKey.g;
	}
	@Override
	public byte[] getPublicKey() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext getEmptyCiphertext() {
		return new PaillierCiphertext(BigInteger.ONE, this);
	}

	@Override
	public AdditiveCiphertext encrypt(BigInteger m, Random rand) {
		if(n2 == null) n2 = n.pow(2);
		if(m.compareTo(n) >= 0) {
			System.out.println("Too big, handle later");
		}
		
		BigInteger r = generateEphemeral(rand);
	
		BigInteger cipher = g.modPow(m,n2).multiply(r.modPow(n, n2)).mod(n2);
		
		return new PaillierCiphertext(cipher, new PaillierPubKey(this));
	}
	
	@Override 
	public boolean equals(Object key) {
		try {
			PaillierPubKey temp = (PaillierPubKey) key;
			return n == temp.n && g == temp.g;
		}
		catch(Exception e) {
			return false;
		}
	}
	public BigInteger getN2() {
		if(n2 == null) n2 = n.pow(2);
		return n2;
	}
	public BigInteger getN() {
		return n;
	}
	@Override
	public AdditiveCiphertext encrypt(BigInteger m, BigInteger r) {
		if(n2 == null) n2 = n.pow(2);
		if(m.compareTo(n) >= 0) {
			System.out.println("Too big, handle later");
		}
		
		BigInteger cipher = g.modPow(m,n2).multiply(r.modPow(n, n2)).mod(n2);
		
		return new PaillierCiphertext(cipher, new PaillierPubKey(this));
	}
	@Override
	public BigInteger getOrder() {
		return n;
	}
	
	public BigInteger getG() {
		return g;
	}
	@Override
	public BigInteger generateEphemeral(Random rand) {
		BigInteger r;
		do {
			r = new BigInteger(n.bitLength(), rand).mod(n);
		}while(!r.gcd(n).equals(BigInteger.ONE));
		return r;
	}
	@Override
	public ZKPProtocol getZKPforProofOfEncryption() {
		return new PaillierProofOfZero();
	}
	@Override
	public CryptoData getZKEnvironment() {
		// TODO Auto-generated method stub
		return new CryptoDataArray(new BigInteger[] {getG(), getN(), getN2()});
	}
	
}
