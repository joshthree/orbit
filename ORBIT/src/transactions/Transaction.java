package transactions;

import java.io.Serializable;

public interface Transaction extends Serializable {
	long getPosition();
	void setPosition(long position);

	boolean verifyTransaction(ProcessedBlockchain b);
	
	byte[] getBytes();
}
