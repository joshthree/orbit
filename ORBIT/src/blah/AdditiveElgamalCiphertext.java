package blah;

import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class AdditiveElgamalCiphertext extends AdditiveCiphertext implements Externalizable  {

	/**
	 * 
	 */
	private static final long serialVersionUID = 508970794714992682L;

	private ECPoint cipher;
	private ECPoint ephemeral;
	private AdditiveElgamalPubKey pub;

	public AdditiveElgamalCiphertext() {
	}
	public AdditiveElgamalCiphertext(ECPoint cipher, ECPoint ephemeral, AdditiveElgamalPubKey pub) {
		this.cipher = cipher;
		this.ephemeral = ephemeral;
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
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(this.ephemeral), new ECPointData(cipher)});
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
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(this.ephemeral), new ECPointData(cipher)});
		toReturn[1] = pub.getZKZeroEnvironment();
		return toReturn;
	}
	@Override
	public CryptoData[] getRerandomizationProverData(AdditiveCiphertext original, BigInteger ephemeral,
			SecureRandom rand) {
		AdditiveCiphertext proofCipher = this.homomorphicAdd(original.negate());
		return proofCipher.getEncryptionProverData(BigInteger.ZERO, ephemeral, rand);
	}
	@Override
	public CryptoData[] getRerandomizationVerifierData(AdditiveCiphertext original) {
		AdditiveCiphertext proofCipher = this.homomorphicAdd(original.negate());
		return proofCipher.getEncryptionVerifierData(BigInteger.ZERO);
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
	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		pub.writeExternal(out);

		byte[] cipherBytes = cipher.getEncoded(true);
		byte[] ephemeralBytes = ephemeral.getEncoded(true);
		out.writeInt(cipherBytes.length);
		out.write(cipherBytes);
		out.writeInt(ephemeralBytes.length);
		out.write(ephemeralBytes);
	}
	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		pub = new AdditiveElgamalPubKey();
		pub.readExternal(in);
		ECCurve curve = pub.getCurve();

		int cipherSize = in.readInt();
		byte[] cipher = new byte[cipherSize];
		if(in.read(cipher) != cipherSize) {
			throw new IOException("Bad Serialization");
		}
		
		int ephemeralSize = in.readInt();
		byte[] ephemeral = new byte[ephemeralSize];
		if(in.read(ephemeral) != ephemeralSize) {
			throw new IOException("Bad Serialization");
		}
		
		this.cipher = curve.decodePoint(cipher);
		this.ephemeral = curve.decodePoint(ephemeral);
	}
	@Override
	public AdditiveCiphertext negate() {
		return new AdditiveElgamalCiphertext(cipher.negate(), ephemeral.negate(), pub);
	}
	@Override
	public BigInteger negateEphemeral(BigInteger ephemeral) {
		
		return ephemeral.negate().mod(pub.getOrder());
	}


}
