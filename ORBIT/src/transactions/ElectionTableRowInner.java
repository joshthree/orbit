package transactions;

import java.io.Serializable;
import java.math.BigInteger;

import blah.AdditiveCiphertext;
import election.Election;
import election.EncryptedVote;

public class ElectionTableRowInner implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7362659664708369691L;
	public AdditiveCiphertext compare;
	public EncryptedVote[] output1;
	public AdditiveCiphertext output2;
	
	public ElectionTableRowInner(AdditiveCiphertext compare, EncryptedVote[] output1, AdditiveCiphertext output2) {
		this.compare = compare;
		if(output1 != null) {
			this.output1 = output1.clone();
		}
		this.output2 = output2;
	}
	
	public ElectionTableRowInner rerandomize(BigInteger compareRerandomize, BigInteger[][] encryptedVotesRerandomize, BigInteger outputCipherRerandomize, Election election) {
		AdditiveCiphertext compare = this.compare.rerandomize(compareRerandomize, election.getMinerKey());
		
		EncryptedVote[] output1 = null;
		if(this.output1 != null) {
			output1 = new EncryptedVote[this.output1.length];
			for(int i = 0; i < output1.length; i++) {
				output1[i] = this.output1[i].rerandomize(encryptedVotesRerandomize[i], election.getRace(i).getPubKey());
			}
		}
		AdditiveCiphertext output2 = null;
		if(this.output2 != null) {
			output2 = this.output2.rerandomize(outputCipherRerandomize, election.getMinerKey());
		}
	
		return new ElectionTableRowInner(compare, output1, output2);
	}
}
