package blah;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Random;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;

public class PaillierCiphertext extends AdditiveCiphertext{

	/**
	 * 
	 */
	private static final long serialVersionUID = -1549561901729415208L;
	private BigInteger cipher;
	private PaillierPubKey paillierPubKey;
	private transient CryptoData proofOfZeroEnvironment;
	
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
	public CryptoData[] getEncryptionProverData(BigInteger message, BigInteger ephemeral, SecureRandom rand) {
		CryptoData[] toReturn = new CryptoData[3];
		BigInteger cipher = (BigInteger) this.scalarAdd(message.negate()).getCipher();
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(cipher)});
		CryptoData[] secrets;
		if(ephemeral == null) {
			secrets = new CryptoData[1];
		}
		else {
			secrets = new CryptoData[2];
			secrets[1] = new BigIntData(ephemeral);
		}
		secrets[0] = new BigIntData(paillierPubKey.generateEphemeral(rand));
		toReturn[1] = new CryptoDataArray(secrets);
		toReturn[2] = paillierPubKey.getZKZeroEnvironment();
		return toReturn;
	}

	@Override
	public CryptoData[] getEncryptionVerifierData(BigInteger message) {
		CryptoData[] toReturn = new CryptoData[3];
		BigInteger cipher = (BigInteger) this.scalarAdd(message.negate()).getCipher();
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(cipher)});
		toReturn[1] = paillierPubKey.getZKZeroEnvironment();
		return toReturn;
	}

	@Override
	public CryptoData[] getRerandomizationProverData(AdditiveCiphertext original, BigInteger ephemeral,
			SecureRandom rand) {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public CryptoData[] getRerandomizationVerifierData(AdditiveCiphertext original) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext rerandomize(SecureRandom rand) {
		return rerandomize(paillierPubKey.generateEphemeral(rand));
	}

	@Override
	public AdditiveCiphertext rerandomize(BigInteger ephemeral) {
		return homomorphicAdd(paillierPubKey.encrypt(BigInteger.ZERO, ephemeral));
	}

	@Override
	public BigInteger homomorphicSumEphemeral(BigInteger[] ephemerals) {
		BigInteger toReturn = BigInteger.ONE;
		for(int i = 0; i < ephemerals.length; i++) {
			toReturn = toReturn.multiply(ephemerals[i]).mod(paillierPubKey.getN());
		}
		return toReturn;
	}

	@Override
	public BigInteger homomorphicAddEphemeral(BigInteger ephemeral1, BigInteger ephemeral2) {
		return ephemeral1.multiply(ephemeral2).mod(paillierPubKey.getN());
	}

	@Override
	public BigInteger scalarAddEphemeral(BigInteger toAdd, BigInteger ephemeral) {

		return ephemeral;
	}

	@Override
	public BigInteger scalarMultiplyEphemeral(BigInteger toMultiply, BigInteger ephemeral) {
		// TODO Auto-generated method stub
		return ephemeral.modPow(toMultiply, paillierPubKey.getN());
	}


	
	
}
