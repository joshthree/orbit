package blah;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class AdditiveElgamalCiphertext extends AdditiveCiphertext {

	/**
	 * 
	 */
	private static final long serialVersionUID = 508970794714992682L;

	private transient ECPoint cipher;
	private byte[] rawCipher;
	
	private transient ECPoint ephemeral;
	private byte[] rawEphemeral;
	private AdditiveElgamalPubKey pub;
	
	public AdditiveElgamalCiphertext(ECPoint ecPoint, ECPoint ephemeral, AdditiveElgamalPubKey pub) {
		this.cipher = ecPoint;
		this.rawCipher = ephemeral.getEncoded(true);
		
		this.ephemeral = ephemeral;
		this.rawEphemeral = ephemeral.getEncoded(true);
		
		this.pub = pub;
	}
	@Override
	public AdditiveCiphertext homomorphicAdd(AdditiveCiphertext toAdd) {
		
		return new AdditiveElgamalCiphertext(cipher.add((ECPoint) toAdd.getCipher()), ephemeral.add(((AdditiveElgamalCiphertext) toAdd).getEphemeral()), pub);
	}

	public ECPoint getEphemeral() {
		return ephemeral;
	}
	@Override
	public AdditiveCiphertext scalarAdd(BigInteger toAdd) {
		return new AdditiveElgamalCiphertext(cipher.add(pub.getG().multiply(toAdd)), ephemeral, pub);
	}

	@Override
	public AdditiveCiphertext scalarMultiply(BigInteger toMultiply) {
		return new AdditiveElgamalCiphertext(cipher.multiply(toMultiply), ephemeral.multiply(toMultiply), pub);
	}

	@Override
	public AdditiveCiphertext getEmptyEncryption() {
		// TODO Auto-generated method stub
		return pub.encrypt(BigInteger.ZERO, BigInteger.ZERO);
	}

	@Override
	protected void mutableAdd(AdditiveCiphertext toAdd) {
		cipher = cipher.add((ECPoint) toAdd.getCipher());
		ephemeral = ephemeral.add(((AdditiveElgamalCiphertext) toAdd).getEphemeral());
		
	}

	@Override
	public CryptoData[] getEncryptionProverData(BigInteger message, BigInteger ephemeral, SecureRandom rand) {

		CryptoData[] toReturn = new CryptoData[3];
		ECPoint cipher = (ECPoint) this.scalarAdd(message.negate()).getCipher();
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(cipher)});
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
	public Object getCipher() {
		// TODO Auto-generated method stub
		return cipher;
	}

	@Override
	public BigInteger getValue() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Pub_Key getPub_Key() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveCiphertext rerandomize(SecureRandom rand) {
		return rerandomize(pub.generateEphemeral(rand));
	}

	@Override
	public AdditiveCiphertext rerandomize(BigInteger ephemeral) {
		return homomorphicAdd(pub.encrypt(BigInteger.ZERO, ephemeral));
	}
	@Override
	public CryptoData[] getEncryptionVerifierData(BigInteger message) {
		CryptoData[] toReturn = new CryptoData[2];
		ECPoint cipher = (ECPoint) this.scalarAdd(message.negate()).getCipher();
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(cipher)});
		toReturn[1] = pub.getZKZeroEnvironment();
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
	public BigInteger homomorphicSumEphemeral(BigInteger[] ephemerals) {
		BigInteger toReturn = ephemerals[0];
		for(int i = 1; i < ephemerals.length; i++) {
			toReturn = toReturn.add(ephemerals[i]).mod(pub.getOrder());
		}
		return toReturn;
	}
	@Override
	public BigInteger homomorphicAddEphemeral(BigInteger ephemeral1, BigInteger ephemeral2) {
		return ephemeral1.add(ephemeral2);
	}
	@Override
	public BigInteger scalarAddEphemeral(BigInteger toAdd, BigInteger ephemeral) {
		return ephemeral;
	}
	@Override
	public BigInteger scalarMultiplyEphemeral(BigInteger toMultiply, BigInteger ephemeral) {
		return ephemeral.multiply(toMultiply);
	}


}
