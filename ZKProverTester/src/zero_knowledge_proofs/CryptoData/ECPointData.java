package zero_knowledge_proofs.CryptoData;

import java.math.BigInteger;
import java.security.spec.EllipticCurve;
import java.util.Base64;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public final class ECPointData extends CryptoData {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5968736215439976858L;
	private byte[] data;
	private transient ECPoint p;
	
	public ECPointData(ECPoint p)
	{
		data = p.getEncoded(true);
		this.p = p;
	}
	@Override
	public CryptoData[] getCryptoDataArray() {
		return null;
	}
	
	@Override
	public ECPoint getECPointData(ECCurve c) {
		if(p != null) return p;
		return c.decodePoint(data);
	}
	
	@Override
	public int size() {
		return 1;
	}

	@Override
	public String toString()
	{
		return String.format("(%s)", new BigInteger(data));
	}
	
	@Override
	public String toString64()
	{
		return String.format("(%s)", Base64.getEncoder().encodeToString(data));
	}
	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return data;
	}
	@Override
	public boolean equals(Object o) {
		ECPointData other = null;
		try {
			other = (ECPointData) o;
		}catch(ClassCastException e) {
			e.printStackTrace();
			System.out.println("this = " + this);
			System.out.println("o = " + o);
		}
		return (p.equals(other.p));
	}
}
