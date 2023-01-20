package transactions;

public interface Transaction {
	long getPosition();
	void setPosition(long position);

	boolean verifyTransaction(ProcessedBlockchain b);
	
	byte[] getBytes();
}
