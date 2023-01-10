package election.multiCipherSVHNw;

import election.VoterDecision;

public class SVHNwVoterDecisionMulti implements VoterDecision {
	
	private int decision;
	
	public SVHNwVoterDecisionMulti(int decision) {
		
		this.decision = decision;
		
	}
	
	public int getDecision() {
		return decision;
	}

}
