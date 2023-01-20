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
	private transient CryptoData proofOfZeroEnvironment;
	
	public PaillierCiphertext(BigInteger cipher) {
		// TODO Auto-generated constructor stub
		this.cipher = cipher;
	}

	@Override
	public AdditiveCiphertext homomorphicAdd(AdditiveCiphertext toAdd, Additive_Pub_Key pub) {
		return new PaillierCiphertext(cipher.multiply(((PaillierCiphertext) toAdd).cipher).mod(((PaillierPubKey) pub).getN2()));
	}

	@Override
	public AdditiveCiphertext scalarMultiply(BigInteger toMultiply, Additive_Pub_Key pub) {
		return new PaillierCiphertext(cipher.modPow(toMultiply, ((PaillierPubKey) pub).getN2()));
	}

	@Override
	protected void mutableAdd(AdditiveCiphertext toAdd, Additive_Pub_Key pub) {
		cipher = cipher.multiply(((PaillierCiphertext) toAdd).cipher);		
	}

	@Override
	public BigInteger getCipher(Pub_Key pub) {
		return cipher;
	}

	
	@Override
	public String toString() {
		return cipher.toString();
	}

	@Override
	public BigInteger getValue(Pub_Key pub) {
		return cipher;
	}

	@Override
	public AdditiveCiphertext scalarAdd(BigInteger toAdd, Additive_Pub_Key pub) {		
		return this.homomorphicAdd(pub.encrypt(toAdd, BigInteger.ONE), pub);
	}

	@Override
	public CryptoData[] getEncryptionProverData(BigInteger message, BigInteger ephemeral, SecureRandom rand, Additive_Pub_Key pub) {
		CryptoData[] toReturn = new CryptoData[3];
		BigInteger cipher = (BigInteger) this.scalarAdd(message.negate(), pub).getCipher(pub);
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(cipher)});
		CryptoData[] secrets;
		if(ephemeral == null) {
			secrets = new CryptoData[1];
		}
		else {
			secrets = new CryptoData[2];
			secrets[1] = new BigIntData(ephemeral);
		}
		secrets[0] = new BigIntData(pub.generateEphemeral(rand));
		toReturn[1] = new CryptoDataArray(secrets);
		toReturn[2] = pub.getZKZeroEnvironment();
		return toReturn;
	}

	@Override
	public CryptoData[] getEncryptionVerifierData(BigInteger message, Additive_Pub_Key pub) {
		CryptoData[] toReturn = new CryptoData[3];
		BigInteger cipher = (BigInteger) this.scalarAdd(message.negate(), pub).getCipher(pub);
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new BigIntData(cipher)});
		toReturn[1] = pub.getZKZeroEnvironment();
		return toReturn;
	}

	@Override
	public CryptoData[] getRerandomizationProverData(AdditiveCiphertext original, BigInteger ephemeral,
			SecureRandom rand, Additive_Pub_Key pub) {
		// TODO Auto-generated method stub
		return null;
	}
	@Override
	public CryptoData[] getRerandomizationVerifierData(AdditiveCiphertext original, Additive_Pub_Key pub) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext rerandomize(SecureRandom rand, Additive_Pub_Key pub) {
		return rerandomize(pub.generateEphemeral(rand), pub);
	}

	@Override
	public AdditiveCiphertext rerandomize(BigInteger ephemeral, Additive_Pub_Key pub) {
		return homomorphicAdd(pub.encrypt(BigInteger.ZERO, ephemeral), pub);
	}

	@Override
	public BigInteger homomorphicSumEphemeral(BigInteger[] ephemerals, Additive_Pub_Key pub) {
		BigInteger toReturn = BigInteger.ONE;
		for(int i = 0; i < ephemerals.length; i++) {
			toReturn = toReturn.multiply(ephemerals[i]).mod(((PaillierPubKey) pub).getN());
		}
		return toReturn;
	}

	@Override
	public BigInteger homomorphicAddEphemeral(BigInteger ephemeral1, BigInteger ephemeral2, Additive_Pub_Key pub) {
		return ephemeral1.multiply(ephemeral2).mod(((PaillierPubKey) pub).getN());
	}

	@Override
	public BigInteger scalarAddEphemeral(BigInteger toAdd, BigInteger ephemeral, Additive_Pub_Key pub) {

		return ephemeral;
	}

	@Override
	public BigInteger scalarMultiplyEphemeral(BigInteger toMultiply, BigInteger ephemeral, Additive_Pub_Key pub) {
		// TODO Auto-generated method stub
		return ephemeral.modPow(toMultiply, ((PaillierPubKey) pub).getN());
	}

	@Override
	public AdditiveCiphertext negate(Additive_Pub_Key pub) {
		return new PaillierCiphertext(cipher.modInverse(((PaillierPubKey) pub).getN2()));
	}

	@Override
	public BigInteger negateEphemeral(BigInteger ephemeral, Additive_Pub_Key pub) {
		return ephemeral.modInverse(((PaillierPubKey) pub).getN());
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return cipher.toByteArray();
	}


	
	
}
