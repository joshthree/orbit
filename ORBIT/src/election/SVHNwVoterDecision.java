package election;

public class SVHNwVoterDecision implements VoterDecision {
	
	private int decision;
	
	public SVHNwVoterDecision(int decision) {
		
		this.decision = decision;
		
	}
	
	public int getDecision() {
		return decision;
	}

}
