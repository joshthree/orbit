package blah;

import org.bouncycastle.math.ec.ECCurve;

public class ECGroup implements Group {
	private ECCurve curve;
	public ECGroup(ECCurve curve) {
		this.curve = curve;
	}
	@Override
	public boolean equals(Object other) {
		if(other instanceof ECGroup) {
			if(curve.equals(((ECGroup)other).curve)) {
				return true;
			}
			else return false;
		}
		return false;
	}
	
}
