package blah;

import java.math.BigInteger;

public class PaillierGroup implements Group {
	private BigInteger n;
	public PaillierGroup(BigInteger n) {
		this.n = n;
	}
	@Override
	public boolean equals(Object other) {
		if(other instanceof PaillierGroup) {
			if(n.equals(((PaillierGroup)other).n)) {
				return true;
			}
			else return false;
		}
		return false;
	}
	
}
