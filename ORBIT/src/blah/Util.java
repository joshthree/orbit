package blah;

public abstract class Util {
	public static final void destroyBigInteger(java.math.BigInteger destroyThis) {
	    try {
	        java.lang.reflect.Field f = java.math.BigInteger.class.getDeclaredField("mag");
	        f.setAccessible(true);
	        f.set(destroyThis, new int[] { 0 });
	        f.setAccessible(false);
	        f = java.math.BigInteger.class.getDeclaredField("signum");
	        f.setAccessible(true);
	        f.setInt(destroyThis, 0);
	        f.setAccessible(false);
	    } catch (Throwable e) {
	        e.printStackTrace();
	    }
	}
}
