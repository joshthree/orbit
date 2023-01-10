package blah;

import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Random;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ElgamalPubKey implements Pub_Key {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7623685611084207477L;
	private ECPoint g;
	private ECPoint y;
	
	@Override
	public byte[] getPublicKey() {
		// TODO Auto-generated method stub  return c as byte array
		return null;
	}

	@Override
	public Ciphertext getEmptyCiphertext() {
		// TODO Auto-generated method stub 
		return encrypt(BigInteger.ONE, BigInteger.ZERO);
	}

	@Override
	public Ciphertext encrypt(BigInteger m, Random rand) {
		// TODO Auto-generated method stub
		return null;
	}
	private Ciphertext encrypt(BigInteger m, BigInteger r) {
		// TODO Auto-generated method stub
		return null;
	}
	public BigInteger getG() {
		// TODO Auto-generated method stub  return c as byte array
		return g;
	}
	public BigInteger getP() {
		// TODO Auto-generated method stub  return c as byte array
		return p;
	}

	@Override
	public void writeExternal(ObjectOutput out) throws IOException {
		byte[] gBytes = g.getEncoded(true);
		byte[] yBytes = y.getEncoded(true);
		out.writeInt(gBytes.length);
		out.write(gBytes);
		out.writeInt(yBytes.length);
		out.write(yBytes);
		ECCurve curve = y.getCurve();
		if(curve instanceof ECCurve.Fp) {
			out.writeShort(1);
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
			out.writeShort(2);
		}
		else {
			throw new InputMismatchException("Curve is not supported");
		}
		
	}

	@Override
	public void readExternal(ObjectInput in) throws IOException, ClassNotFoundException {
		in.read
		
	}

	@Override
	public Ciphertext encrypt(BigInteger m, SecureRandom rand) {
		// TODO Auto-generated method stub
		return null;
	}


}
