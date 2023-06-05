package blah;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.InputMismatchException;
import java.util.Random;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.F2m;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECProofOfPrechosenExponentProver;
import zero_knowledge_proofs.ECSchnorrProver;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;


public class AdditiveElgamalPubKey implements Additive_Pub_Key {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7623685611084207477L;
	private ECPoint g;
	private ECPoint y;
	private transient ZKPProtocol ddhZKP = new ECEqualDiscreteLogsProver();
	public AdditiveElgamalPubKey() {
		g = y = null;
	}
	public AdditiveElgamalPubKey(ECPoint g, ECPoint y) {
		this.g = g;
		this.y = y;
	}
	
	@Override
	public byte[] getPublicKey() {
		return y.getEncoded(true);
	}

	public ECPoint getG() {
		return g;
	}
	public ECPoint getY() {
		return y;
	}
	@Override
	public AdditiveElgamalCiphertext getEmptyCiphertext() {
		return encrypt(BigInteger.ZERO, BigInteger.ZERO);
	}
 
	@Override
	public AdditiveElgamalCiphertext encrypt(BigInteger m, SecureRandom rand) {
		
		return encrypt(m, generateEphemeral(rand));
	}

	@Override
	public ZKPProtocol getZKPforProofOfEncryption() {
		if(ddhZKP == null) ddhZKP = new ECEqualDiscreteLogsProver();
		return ddhZKP;
	}

	@Override
	public AdditiveElgamalCiphertext encrypt(BigInteger m, BigInteger r) {
		return new AdditiveElgamalCiphertext(g.multiply(m).add(y.multiply(r)), g.multiply(r));
	}

	@Override
	public BigInteger getOrder() {
		return y.getCurve().getOrder();
	}

	@Override
	public BigInteger generateEphemeral(SecureRandom rand) {
		return ZKToolkit.random(y.getCurve().getOrder(), rand);
	}

	@Override
	public CryptoData getZKZeroEnvironment() {
		return new CryptoDataArray(new CryptoData[] {new ECCurveData(g.getCurve(), g), new ECPointData(y)});
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		ECCurve curve = y.getCurve();
		byte[] order = curve.getOrder().toByteArray();
		byte[] cofactor = curve.getCofactor().toByteArray();
		out.writeInt(order.length);
		out.write(order, 0, order.length);

		out.writeInt(cofactor.length);
		out.write(cofactor, 0, cofactor.length);
		if(curve instanceof ECCurve.Fp) {
			out.writeByte(1);
			ECCurve.Fp curve2 = (ECCurve.Fp) curve;
			byte[] a = curve2.getA().getEncoded();
			byte[] b = curve2.getB().getEncoded();
			byte[] q = curve2.getQ().toByteArray();
			
			out.writeInt(a.length);
			out.write(a, 0, a.length);
			
			out.writeInt(b.length);
			out.write(b, 0, b.length);
			
			out.writeInt(q.length);
			out.write(q, 0, q.length);
			
		}
		else if(curve instanceof ECCurve.F2m) {
			ECCurve.F2m curve2 = (ECCurve.F2m) curve;
			if(curve2.isTrinomial()) {
				out.writeByte(2);
				byte[] a = curve2.getA().getEncoded();
				byte[] b = curve2.getB().getEncoded();
				int m = curve2.getM();
				out.writeInt(a.length);
				out.write(a, 0, a.length);
				out.writeInt(b.length);
				out.write(b, 0, b.length);
				out.writeInt(m);
				out.writeInt(curve2.getK1());
				out.writeInt(curve2.getK2());
				out.writeInt(curve2.getK3());
			}
			else {
				out.writeByte(3);
				byte[] a = curve2.getA().getEncoded();
				byte[] b = curve2.getB().getEncoded();
				int m = curve2.getM();
				out.writeInt(a.length);
				out.write(a, 0, a.length);
				out.writeInt(b.length);
				out.write(b, 0, b.length);
				out.writeInt(m);
				out.writeInt(m);
				out.writeInt(curve2.getK1());
			}
		}
		else {
			out.writeByte(4);
			byte[] curveBytes = curve.getClass().getName().getBytes();
			out.writeInt(curveBytes.length);
			out.write(curveBytes,0,curveBytes.length);
		}
		
		byte[] gBytes = g.getEncoded(true);
		byte[] yBytes = y.getEncoded(true);
		out.writeInt(gBytes.length);
		out.write(gBytes, 0, gBytes.length);
		out.writeInt(yBytes.length);
		out.write(yBytes, 0, yBytes.length);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		ECCurve curve = null;
		int orderSize = in.readInt();

		byte[] order = new byte[orderSize];
		int blah;
		if((blah = in.read(order, 0, orderSize)) != orderSize) {
			throw new IOException(String.format("Bad Serialization: order -- %d != %d", orderSize, blah));
		}
		int cofactorSize = in.readInt();
		byte[] cofactor = new byte[cofactorSize];
		if((blah = in.read(cofactor, 0, cofactorSize)) != cofactorSize) {
			throw new IOException(String.format("Bad Serialization: cofactor -- %d != %d", cofactorSize, blah));
		}
		
		byte curveType = in.readByte();
		
		if(curveType == 1) {
			int aSize = in.readInt();
			byte[] a = new byte[aSize];
			if(in.read(a, 0, aSize) != aSize) {
				throw new IOException("Bad Serialization");
			}
			int bSize = in.readInt();
			byte[] b = new byte[bSize];
			if(in.read(b, 0, bSize) != bSize) {
				throw new IOException("Bad Serialization");
			}
			int qSize = in.readInt();
			byte[] q = new byte[qSize];
			if(in.read(q, 0, qSize) != qSize) {
				throw new IOException("Bad Serialization");
			}
			curve = new ECCurve.Fp(new BigInteger(q), new BigInteger(a), new BigInteger(b), new BigInteger(order), new BigInteger(cofactor));
		}
		
		if(curveType == 2) {
			int aSize = in.readInt();
			byte[] a = new byte[aSize];
			if(in.read(a, 0, aSize) != aSize) {
				throw new IOException("Bad Serialization");
			}
			int bSize = in.readInt();
			byte[] b = new byte[bSize];
			if(in.read(b, 0, bSize) != bSize) {
				throw new IOException("Bad Serialization");
			}
			int m = in.readInt();
			int k1 = in.readInt();
			int k2 = in.readInt();
			int k3 = in.readInt();
			curve = new ECCurve.F2m(m, k1, k2, k3, new BigInteger(a), new BigInteger(b), new BigInteger(order), new BigInteger(cofactor));
		}

		if(curveType == 3) {
			int aSize = in.readInt();
			byte[] a = new byte[aSize];
			if(in.read(a, 0, aSize) != aSize) {
				throw new IOException("Bad Serialization");
			}
			int bSize = in.readInt();
			byte[] b = new byte[bSize];
			if(in.read(b, 0, bSize) != bSize) {
				throw new IOException("Bad Serialization");
			}
			int m = in.readInt();
			int k1 = in.readInt();
			curve = new ECCurve.F2m(m, k1, new BigInteger(a), new BigInteger(b), new BigInteger(order), new BigInteger(cofactor));
		}
		if(curveType == 4) {
			try {
				int classNameSize = in.readInt();
				byte[] curveBytes = new byte[classNameSize];
				in.read(curveBytes,0, classNameSize);
				String curveClassName = new String(curveBytes);
				Class<?> cls = Class.forName(curveClassName);
				curve = (ECCurve) cls.getConstructors()[0].newInstance(new Object[0]);
			} catch (Exception e) {
				System.err.println("gfdjshglfskdjhlkj");
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			throw new IOException("Bad Serialization");
		}
		
		int gSize = in.readInt();
		byte[] g = new byte[gSize];
		in.read(g, 0, gSize);

		int ySize = in.readInt();
		byte[] y = new byte[ySize];
		in.read(y, 0, ySize);
		this.g = curve.decodePoint(g);
		this.y = curve.decodePoint(y);
	}
	public ECCurve getCurve() {
		return g.getCurve();
	}
	
	//Creates a combined pub key that can be decrypted by first decrypting with this's priv, then by decrypting by otherKey's priv (or vice versa)
	@Override
	public Additive_Pub_Key combineKeys(Additive_Pub_Key otherKey) {
		AdditiveElgamalPubKey otherK = (AdditiveElgamalPubKey) otherKey;
		if (!otherK.getG().equals(g)) {
			throw new InputMismatchException("Non-matching generators between keys");
		}
		return new AdditiveElgamalPubKey(g, y.add(otherK.y));
	}
	@Override
	public Additive_Pub_Key removeKey(Additive_Pub_Key otherKey) {
		AdditiveElgamalPubKey otherK = (AdditiveElgamalPubKey) otherKey;
		if (!otherK.getG().equals(g)) {
			throw new InputMismatchException("Non-matching generators between keys");
		}
		return new AdditiveElgamalPubKey(g, y.add(otherK.y.negate()));
	}
	@Override
	public ZKPProtocol getZKPforRerandomization() {
		return this.getZKPforProofOfEncryption();
	}
	@Override
	public byte[] getBytes() {
		
		ByteArrayOutputStream out1 = new ByteArrayOutputStream();
		try {
			ObjectOutput out = new ObjectOutputStream(out1);
			out.writeObject(this);
		} catch (IOException e) {
			e.printStackTrace();
		}
		return out1.toByteArray();
	}
	@Override
	public boolean isSharable() {
		// TODO Auto-generated method stub
		return true;
	}
	

}
