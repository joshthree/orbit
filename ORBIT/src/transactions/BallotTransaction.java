package transactions;

import blah.AdditiveCiphertext;
import election.EncryptedVote;

public class BallotTransaction implements Transaction {
	private SourceTransaction[] ringMembers;
	private EncryptedVote[] voterVotes;
	
	private EncryptedVote[] countedVotes;
	
	private AdditiveCiphertext password;
	//Work in constructor:
	//public BallotTransaction(Transaction[] ringMembers, int source, Additive_Priv_Key signingKey, BigInteger password, Election election, EncryptedVote[] votes){
		//We will implement Dummy Ballot Part 1
	//}
	
	//public ??? adjustForPassword(Additive_Priv_Key minerKey, ObjectInputStream[] in, ObjectOutputStream[] out)
}
