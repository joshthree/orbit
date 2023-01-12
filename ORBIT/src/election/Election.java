package election;

import java.security.SecureRandom;
import java.util.InputMismatchException;

import blah.AdditiveElgamalPubKey;
import blah.Additive_Pub_Key;

public class Election {
	
	private Race[] races;
	private String desc;
	private AdditiveElgamalPubKey minerKey;
	
	public Election(Race[] races, String desc, AdditiveElgamalPubKey minerKey) {
		this.races = races;
		this.desc = desc;
		this.minerKey = minerKey;
	}

	public EncryptedVote[] vote(VoterDecision[] voterDecisions, SecureRandom rand) {
		
		EncryptedVote[] encryptedVote = new EncryptedVote[races.length];
		
		if (voterDecisions.length != races.length)
			throw new InputMismatchException("# of voterDecisions didn't match # of races");
		for (int i = 0; i < voterDecisions.length; i++) {
			encryptedVote[i] = races[i].vote(voterDecisions[i], rand);
		}
		return encryptedVote;
	}
	
	public boolean verify(EncryptedVote[] encryptedVotes) {
		
		if (encryptedVotes.length != races.length)
			throw new InputMismatchException("# of encryptVotes didn't match # of races");
		try { 
			for (int i = 0; i < encryptedVotes.length; i++) {
				if (!races[i].verify(encryptedVotes[i])) {
					return false;
				}
			}
		}
		catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}
	public AdditiveElgamalPubKey getMinerKey() {
		return minerKey;
	}
}
