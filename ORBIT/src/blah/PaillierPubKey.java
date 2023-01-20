package blah;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Random;

import org.bouncycastle.util.Arrays;

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
	private transient CryptoData envZero;
	
	private ZKPProtocol pPoZ = new PaillierProofOfZero();
	
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
		return new PaillierCiphertext(BigInteger.ONE);
	}

	@Override
	public AdditiveCiphertext encrypt(BigInteger m, SecureRandom rand) {
		if(n2 == null) n2 = n.pow(2);
		if(m.compareTo(n) >= 0) {
			System.out.println("Too big, handle later");
		}
		
		BigInteger r = generateEphemeral(rand);
	
		BigInteger cipher = g.modPow(m,n2).multiply(r.modPow(n, n2)).mod(n2);
		
		return new PaillierCiphertext(cipher);
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
		if(!r.gcd(n2).equals(BigInteger.ONE)) {
			throw new ArithmeticException("r is not relatively prime.");
		}
		if(m.compareTo(n) >= 0) {
			System.out.println("Too big, handle later");
		}
		
		BigInteger cipher = g.modPow(m,n2).multiply(r.modPow(n, n2)).mod(n2);
		return new PaillierCiphertext(cipher);
	}
	@Override
	public BigInteger getOrder() {
		return n;
	}
	
	public BigInteger getG() {
		return g;
	}
	@Override
	public BigInteger generateEphemeral(SecureRandom rand) {
		BigInteger r;
		do {
			r = new BigInteger(n.bitLength(), rand).mod(n);
		}while(!r.gcd(n2).equals(BigInteger.ONE));
		return r;
	}
	@Override
	public ZKPProtocol getZKPforProofOfEncryption() {
		if (pPoZ == null) new PaillierProofOfZero();
		return pPoZ;
	}
	@Override
	public CryptoData getZKZeroEnvironment() {
		if(envZero == null) envZero = new CryptoDataArray(new BigInteger[] {getN(), getN2(), getG()});
		return envZero;
	}
	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		out.writeObject(n);
		out.writeObject(g);
		
	}
	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		n = (BigInteger) in.readObject();
		g = (BigInteger) in.readObject();
		n2 = n.pow(2);
		
	}
	@Override
	public Additive_Pub_Key combineKeys(Additive_Pub_Key otherKey) {
		throw new InputMismatchException("Not implemented for Paillier");
	}
	@Override
	public Additive_Pub_Key removeKey(Additive_Pub_Key otherKey) {
		throw new InputMismatchException("Not implemented for Paillier");
	}
	@Override
	public ZKPProtocol getZKPforRerandomization() {
		return this.getZKPforProofOfEncryption();
	}
	@Override
	public byte[] getBytes() {
		return Arrays.concatenate(n.toByteArray(), g.toByteArray());
	}
	
}
