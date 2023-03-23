package transactions;

import java.io.Serializable;
import java.util.ArrayList;

public class ProcessedBlockchain implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7810429571010390645L;
	/**
	 * 
	 */
	private ArrayList<Transaction> transaction;
	
	public ProcessedBlockchain() {
		transaction = new ArrayList<Transaction>();
	}
	
	public Transaction getTransaction(long ringMembersPos) {
		return transaction.get((int) ringMembersPos);
	}
	public void addTransaction(Transaction t) {
		t.setPosition(transaction.size());
		transaction.add(t);
		
	}

	public int size() {
		return transaction.size();
	}
}
