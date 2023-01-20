package election;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.InputMismatchException;

import org.bouncycastle.util.Arrays;

import blah.AdditiveElgamalPubKey;
import blah.Additive_Pub_Key;

public class Election implements Serializable{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 2563803447247240353L;
	private Race[] races;
	private String desc;
	private AdditiveElgamalPubKey minerKey;
	private int rowCount;
	private int abbridgedRowCount;
	private int resetRowCount;
	
	public Election(Race[] races, String desc, AdditiveElgamalPubKey minerKey, int rowCount, int abbridgedRowCount, int resetRowCount) {
		this.races = races;
		this.desc = desc;
		this.minerKey = minerKey;
		this.rowCount = rowCount;
		this.abbridgedRowCount = abbridgedRowCount;
		this.resetRowCount = resetRowCount;
		if(abbridgedRowCount > rowCount) throw new InputMismatchException("rowCount should be greater than abbridgedRowCount.");
		if(rowCount % 2 != 0) throw new InputMismatchException("rowCount must be even.");
		if(resetRowCount > abbridgedRowCount) throw new InputMismatchException("abbridgedRowCount should be greater than resetRowCount.");
		if(resetRowCount < 1) throw new InputMismatchException("resetRowCount must be greater than one.");
		if(resetRowCount == abbridgedRowCount) throw new InputMismatchException("resetRowCount must be strictly less than abbridgedRowCount..");
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
	private final BigInteger LONGMOD = BigInteger.valueOf(Long.MAX_VALUE);
	public byte[] getBytes() {
		byte[][] toReturn = new byte[3][];
		if (desc != null) {
			toReturn[0] = desc.getBytes();
		} else {
			toReturn[0] = "null".getBytes();
		}
		toReturn[1] = minerKey.getBytes();
		byte[][] temp = new byte[races.length][];
		for(int i = 0; i < races.length; i++) {
			temp[i] = races[i].getBytes();
		}
		toReturn[2] = Arrays.concatenate(temp);
		
		return Arrays.concatenate(toReturn);
	}

	public int getRowCount() {
		// TODO Auto-generated method stub
		return rowCount;
	}
	public int getAbbridgedRowCount() {
		// TODO Auto-generated method stub
		return abbridgedRowCount;
	}
	public int getResetRowCount() {
		// TODO Auto-generated method stub
		return resetRowCount;
	}

	public Race getRace(int i) {
		// TODO Auto-generated method stub
		return races[i];
	}
	public int getNumRace() {
		// TODO Auto-generated method stub
		return races.length;
	}
}

