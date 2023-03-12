package blah;

import java.io.ByteArrayOutputStream;
import java.io.Externalizable;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

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
	private transient ECPoint ephemeral;
	private byte[] cipherBytes;
	private byte[] ephemeralBytes;
	

	public AdditiveElgamalCiphertext() {
	}
	public AdditiveElgamalCiphertext(ECPoint cipher, ECPoint ephemeral) {
		this.cipher = cipher;
		this.ephemeral = ephemeral;
		
		cipherBytes = cipher.getEncoded(true);
		ephemeralBytes = ephemeral.getEncoded(true);
	}
	@Override
	public AdditiveElgamalCiphertext homomorphicAdd(AdditiveCiphertext toAdd, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return new AdditiveElgamalCiphertext(cipher.add((ECPoint) toAdd.getCipher(pub)), ephemeral.add(((AdditiveElgamalCiphertext) toAdd).getEphemeral(pub)));
	}

	public ECPoint getEphemeral(Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return ephemeral;
	}
	@Override
	public AdditiveElgamalCiphertext scalarAdd(BigInteger toAdd, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return new AdditiveElgamalCiphertext(cipher.add(((AdditiveElgamalPubKey) pub).getG().multiply(toAdd)), ephemeral);
	}

	@Override
	public AdditiveElgamalCiphertext scalarMultiply(BigInteger toMultiply, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return new AdditiveElgamalCiphertext(cipher.multiply(toMultiply), ephemeral.multiply(toMultiply));
	}

	@Override
	protected void mutableAdd(AdditiveCiphertext toAdd, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		cipher = cipher.add((ECPoint) toAdd.getCipher(pub));
		ephemeral = ephemeral.add(((AdditiveElgamalCiphertext) toAdd).getEphemeral(pub));
		
	}

	@Override
	public CryptoData[] getEncryptionProverData(BigInteger message, BigInteger ephemeral, SecureRandom rand, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}

		CryptoData[] toReturn = new CryptoData[3];
		ECPoint cipher = (ECPoint) this.scalarAdd(message.negate(), pub).getCipher(pub);
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
	public ECPoint getCipher(Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return cipher;
	}

	@Override
	public BigInteger getValue(Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public AdditiveElgamalCiphertext rerandomize(SecureRandom rand, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return rerandomize(((Additive_Pub_Key) pub).generateEphemeral(rand), pub);
	}

	@Override
	public AdditiveElgamalCiphertext rerandomize(BigInteger ephemeral, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return homomorphicAdd(((AdditiveElgamalPubKey) pub).encrypt(BigInteger.ZERO, ephemeral), (Additive_Pub_Key) pub);
	}
	@Override
	public CryptoData[] getEncryptionVerifierData(BigInteger message, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		CryptoData[] toReturn = new CryptoData[2];
		ECPoint cipher = (ECPoint) this.scalarAdd(message.negate(),pub).getCipher(pub);
		toReturn[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(this.ephemeral), new ECPointData(cipher)});
		toReturn[1] = pub.getZKZeroEnvironment();
		return toReturn;
	}
	@Override
	public CryptoData[] getRerandomizationProverData(AdditiveCiphertext original, BigInteger ephemeral,
			SecureRandom rand, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		AdditiveCiphertext proofCipher = this.homomorphicAdd(original.negate(pub), pub);
		return proofCipher.getEncryptionProverData(BigInteger.ZERO, ephemeral, rand, pub);
	}
	@Override
	public CryptoData[] getRerandomizationVerifierData(AdditiveCiphertext original, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		AdditiveCiphertext proofCipher = this.homomorphicAdd(original.negate(pub), pub);
		return proofCipher.getEncryptionVerifierData(BigInteger.ZERO, pub);
	}
	@Override
	public BigInteger homomorphicSumEphemeral(BigInteger[] ephemerals, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		BigInteger toReturn = ephemerals[0];
		for(int i = 1; i < ephemerals.length; i++) {
			toReturn = toReturn.add(ephemerals[i]).mod(pub.getOrder());
		}
		return toReturn;
	}
	@Override
	public BigInteger homomorphicAddEphemeral(BigInteger ephemeral1, BigInteger ephemeral2, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return ephemeral1.add(ephemeral2);
	}
	@Override
	public BigInteger scalarAddEphemeral(BigInteger toAdd, BigInteger ephemeral, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return ephemeral;
	}
	@Override
	public BigInteger scalarMultiplyEphemeral(BigInteger toMultiply, BigInteger ephemeral, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return ephemeral.multiply(toMultiply);
	}
//	@Override
//	public void writeExternal(ObjectOutput out) throws IOException {
//		byte[] cipherBytes = cipher.getEncoded(true);
//		byte[] ephemeralBytes = ephemeral.getEncoded(true);
//		out.writeInt(cipherBytes.length);
//		out.write(cipherBytes);
//		out.writeInt(ephemeralBytes.length);
//		out.write(ephemeralBytes);
//	}
//	@Override
//	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
//		int cipherSize = in.readInt();
//		byte[] cipher = new byte[cipherSize];
//		if(in.read(cipher) != cipherSize) {
//			throw new IOException("Bad Serialization");
//		}
//		
//		int ephemeralSize = in.readInt();
//		byte[] ephemeral = new byte[ephemeralSize];
//		if(in.read(ephemeral) != ephemeralSize) {
//			throw new IOException("Bad Serialization");
//		}
//		
//		this.cipher = curve.decodePoint(cipher);
//		this.ephemeral = curve.decodePoint(ephemeral);
//	}
	@Override
	public AdditiveElgamalCiphertext negate(Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		return new AdditiveElgamalCiphertext(cipher.negate(), ephemeral.negate());
	}
	@Override
	public BigInteger negateEphemeral(BigInteger ephemeral, Additive_Pub_Key pub) {
		if(cipher == null) {
			ECCurve curve = ((AdditiveElgamalPubKey) pub).getG().getCurve();
			this.cipher = curve.decodePoint(cipherBytes);
			this.ephemeral = curve.decodePoint(ephemeralBytes);
		}
		
		return ephemeral.negate().mod(pub.getOrder());
	}
	@Override
	public byte[] getBytes() {
		return Arrays.concatenate(cipherBytes, ephemeralBytes);
	}
	
	

}
