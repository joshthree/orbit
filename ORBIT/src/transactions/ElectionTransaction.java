package transactions;

import java.nio.MappedByteBuffer;

import org.bouncycastle.util.Arrays;

import election.Election;

public class ElectionTransaction implements Transaction {
	/**
	 * 
	 */
	private static final long serialVersionUID = -1043962846326807051L;
	private long position = -1;
	private Election election;
	public ElectionTransaction(Election election) {
		this.election = election;
	}
	
	@Override
	public long getPosition() {
		// TODO Auto-generated method stub
		return position;
	}

	@Override
	public void setPosition(long position) {
		// TODO Auto-generated method stub
		this.position = position;
	}

	@Override
	public boolean verifyTransaction(ProcessedBlockchain b) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		byte[][] toReturn = new byte[2][];
		toReturn[0] = MappedByteBuffer.wrap(new byte[8]).putLong(position).array();
		toReturn[1] = election.getBytes();
		return Arrays.concatenate(toReturn);
	}
	
	public Election getElection() {
		return election;
	}

}
