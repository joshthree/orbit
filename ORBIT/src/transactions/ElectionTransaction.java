package transactions;

import java.nio.MappedByteBuffer;

import election.Election;

public class ElectionTransaction implements Transaction {
	private long position;
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
		return false;
	}

	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return MappedByteBuffer.wrap(new byte[8]).putLong(position).array();
	}
	
	public Election getElection() {
		return election;
	}

}
