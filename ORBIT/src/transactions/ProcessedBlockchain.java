package transactions;

import java.util.ArrayList;

public class ProcessedBlockchain {
	private ArrayList<Transaction> transaction;
	
	public ProcessedBlockchain() {
		transaction = new ArrayList<Transaction>();
	}
	
	public Transaction getTransaction(int i) {
		return transaction.get(i);
	}
	public void addTransaction(Transaction t) {
		t.setPosition(transaction.size());
		transaction.add(t);
		
	}
}
