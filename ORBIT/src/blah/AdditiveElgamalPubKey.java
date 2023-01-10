package blah;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Random;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECCurve.F2m;
import org.bouncycastle.math.ec.ECPoint;

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
	
	public AdditiveElgamalPubKey(ECPoint g, ECPoint y) {
		this.g = g;
		this.y = y;
	}
	
	@Override
	public byte[] getPublicKey() {
		// TODO Auto-generated method stub  return c as byte array
		return null;
	}

	public ECPoint getG() {
		return g;
	}
	public ECPoint getY() {
		return y;
	}
	@Override
	public AdditiveCiphertext getEmptyCiphertext() {
		return encrypt(BigInteger.ZERO, BigInteger.ZERO);
	}

	@Override
	public AdditiveCiphertext encrypt(BigInteger m, SecureRandom rand) {
		
		return encrypt(m, generateEphemeral(rand));
	}

	@Override
	public ZKPProtocol getZKPforProofOfEncryption() {
		return new ECSchnorrProver();
	}

	@Override
	public AdditiveCiphertext encrypt(BigInteger m, BigInteger r) {
		return new AdditiveElgamalCiphertext(g.multiply(m).add(y.multiply(r)), g.multiply(r), this);
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
		return new CryptoDataArray(new CryptoData[] {new ECCurveData(g.getCurve(), y)});
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		ECCurve curve = y.getCurve();
		byte[] order = curve.getOrder().toByteArray();
		byte[] cofactor = curve.getCofactor().toByteArray();

		out.writeInt(order.length);
		out.write(order);
		
		out.writeInt(cofactor.length);
		out.write(cofactor);
		
		if(curve instanceof ECCurve.Fp) {
			out.writeByte(1);
			ECCurve.Fp curve2 = (ECCurve.Fp) curve;
			byte[] a = curve2.getA().getEncoded();
			byte[] b = curve2.getB().getEncoded();
			byte[] q = curve2.getQ().toByteArray();
			
			out.writeInt(a.length);
			out.write(a);
			
			out.writeInt(b.length);
			out.write(b);
			
			out.writeInt(q.length);
			out.write(q);
			
		}
		else if(curve instanceof ECCurve.F2m) {
			ECCurve.F2m curve2 = (ECCurve.F2m) curve;
			if(curve2.isTrinomial()) {
				out.writeByte(2);
				byte[] a = curve2.getA().getEncoded();
				byte[] b = curve2.getB().getEncoded();
				int m = curve2.getM();
				out.writeInt(a.length);
	
				out.write(a);
				out.writeInt(b.length);
				out.write(b);
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
	
				out.write(a);
				out.writeInt(b.length);
				out.write(b);
				out.writeInt(m);
				out.writeInt(curve2.getK1());
			}
		}
		else {
			try {
				out.writeByte(4);
				out.writeObject(curve.getClass().toString());
				out.writeObject(curve);
			}
			catch(Exception e) {
				throw new InputMismatchException("Non-supported curve");
			}
		}
		
		byte[] gBytes = g.getEncoded(true);
		byte[] yBytes = y.getEncoded(true);
		out.writeInt(gBytes.length);
		out.write(gBytes);
		out.writeInt(yBytes.length);
		out.write(yBytes);
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		ECCurve curve = null;
		int orderSize = in.readInt();
		byte[] order = new byte[orderSize];
		if(in.read(order) != orderSize) {
			throw new IOException("Bad Serialization");
		}
		
		int cofactorSize = in.readInt();
		byte[] cofactor = new byte[cofactorSize];
		if(in.read(cofactor) != cofactorSize) {
			throw new IOException("Bad Serialization");
		}
		
		
		byte curveType = in.readByte();
		
		if(curveType == 1) {
			int aSize = in.readInt();
			byte[] a = new byte[aSize];
			if(in.read(a) != aSize) {
				throw new IOException("Bad Serialization");
			}
			int bSize = in.readInt();
			byte[] b = new byte[bSize];
			if(in.read(b) != bSize) {
				throw new IOException("Bad Serialization");
			}
			int qSize = in.readInt();
			byte[] q = new byte[qSize];
			if(in.read(q) != qSize) {
				throw new IOException("Bad Serialization");
			}
			curve = new ECCurve.Fp(new BigInteger(q), new BigInteger(a), new BigInteger(b), new BigInteger(order), new BigInteger(cofactor));
		}
		
		if(curveType == 2) {
			int aSize = in.readInt();
			byte[] a = new byte[aSize];
			if(in.read(a) != aSize) {
				throw new IOException("Bad Serialization");
			}
			int bSize = in.readInt();
			byte[] b = new byte[bSize];
			if(in.read(b) != bSize) {
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
			if(in.read(a) != aSize) {
				throw new IOException("Bad Serialization");
			}
			int bSize = in.readInt();
			byte[] b = new byte[bSize];
			if(in.read(b) != bSize) {
				throw new IOException("Bad Serialization");
			}
			int m = in.readInt();
			int k1 = in.readInt();
			curve = new ECCurve.F2m(m, k1, new BigInteger(a), new BigInteger(b), new BigInteger(order), new BigInteger(cofactor));
		}
		if(curveType == 4) {
			curve = (ECCurve) in.readObject();
		}
		else {
			throw new IOException("Bad Serialization");
		}
		
		int gSize = in.readInt();
		byte[] g = new byte[gSize];
		if(in.read(g) != gSize) {
			throw new IOException("Bad Serialization");
		}
		
		int ySize = in.readInt();
		byte[] y = new byte[ySize];
		if(in.read(y) != ySize) {
			throw new IOException("Bad Serialization");
		}
		
		this.g = curve.decodePoint(g);
		this.y = curve.decodePoint(y);
	}


}
