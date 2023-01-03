package election;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.SecureRandom;
import java.util.ArrayList;

import blah.Additive_Priv_Key;

public interface Race {
	//voter runs this function to create a vote in this race
	public EncryptedVote vote(VoterDecision v, SecureRandom rand);
	
	//anyone public runs this function to verify a vote is valid
	public boolean verify(EncryptedVote phi);
	
	//government (technically anyone) runs this function to rerandomize and prove rerandomization of vote
	public EncryptedVote reRandomizeVote(EncryptedVote phi, SecureRandom rand);
	
	//government (technically anyone) runs this to get a vote that has an apparent identical result or effect on the race results but is not actually counted
	public EncryptedVote zero_vote(EncryptedVote phi);
	
	//allows the government to work together to decrypt a ballot
	public VoterDecision decrypt(EncryptedVote phi, Additive_Priv_Key p, ObjectInputStream[] in, ObjectOutputStream[] out);
	
	//government runs this to produce race results with proof
	public RaceResults tally(ArrayList<EncryptedVote> cPsi, Additive_Priv_Key p, ObjectInputStream[] in, ObjectOutputStream[] out, SecureRandom rand);
	
	//allows public to verify race results
	public boolean confirm(ArrayList<EncryptedVote> cPsi, RaceResults result);
	
}
