package blah;

import java.math.BigInteger;
import java.util.InputMismatchException;
import java.util.Random;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;

public class PaillierCiphertext extends AdditiveCiphertext{

	/**
	 * 
	 */
	private static final long serialVersionUID = -1549561901729415208L;
	private BigInteger cipher;
	private PaillierPubKey paillierPubKey;
	
	public PaillierCiphertext(BigInteger cipher, Additive_Pub_Key paillierPubKey) {
		// TODO Auto-generated constructor stub
		this.cipher = cipher;
		this.paillierPubKey = (PaillierPubKey) paillierPubKey;
	}

	@Override
	public AdditiveCiphertext homomorphicAdd(AdditiveCiphertext toAdd) {
		if(!paillierPubKey.equals(toAdd.getPub_Key())) {
			throw new InputMismatchException();
		}
		
		return new PaillierCiphertext(cipher.multiply(((PaillierCiphertext) toAdd).cipher).mod(paillierPubKey.getN2()), paillierPubKey);
	}

	@Override
	public AdditiveCiphertext scalarMultiply(BigInteger toMultiply) {
		return new PaillierCiphertext(cipher.modPow(toMultiply, paillierPubKey.getN2()), paillierPubKey);
	}

	@Override
	public AdditiveCiphertext getEmptyEncryption() {
		return new PaillierCiphertext(BigInteger.ONE, paillierPubKey);
	}

	@Override
	protected void mutableAdd(AdditiveCiphertext toAdd) {
		if(!paillierPubKey.equals(toAdd.getPub_Key())) {
			throw new InputMismatchException();
		}
		cipher = cipher.multiply(((PaillierCiphertext) toAdd).cipher);		
	}


	@Override
	public Ciphertext rerandomize(BigInteger r) {
		PaillierCiphertext toReturn = new PaillierCiphertext(cipher.multiply(r.modPow(paillierPubKey.getN(), paillierPubKey.getN2())).mod(paillierPubKey.getN2()), paillierPubKey);
		return toReturn;
	}

	@Override
	public Ciphertext rerandomize(Random rand) {
		BigInteger r = new BigInteger(paillierPubKey.getN().bitLength(), rand);
		return rerandomize(r);
	}

	@Override
	public BigInteger getCipher() {
		return cipher;
	}

	@Override
	public Pub_Key getPub_Key() {
		return paillierPubKey;
	}
	
	@Override
	public String toString() {
		return cipher.toString();
	}

	@Override
	public BigInteger getValue() {
		return cipher;
	}

	@Override
	public AdditiveCiphertext scalarAdd(BigInteger toAdd) {		
		return this.homomorphicAdd(paillierPubKey.encrypt(toAdd, BigInteger.ONE));
	}

	@Override
	public CryptoData getEncryptionProofData(BigInteger message) {
		BigInteger cipher = (BigInteger) this.scalarAdd(message.negate()).getCipher();
		CryptoData toReturn = new BigIntData(cipher);
		return toReturn;
	}
	
	
}
