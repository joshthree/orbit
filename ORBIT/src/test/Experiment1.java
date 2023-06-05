package test;	

public class Experiment1 {
	public static void main(String arg[]) {
		String[] arguments = new String[5];
		arguments[0] = "40";// numRaces = 4;
		arguments[1] = "4";// numCandidates = 4;
		arguments[2] = "50";// numVotes = 50;
		arguments[3] = "20";// miners = 10;
		arguments[4] = "15";// ringSize = 15;
		int[] numRaces = {1,2,20,40,60,80,100};
		int[] numMiners = {5,50,30,20,10};
		for (int j = 0; j < numMiners.length; j++) {
			arguments[3] = String.valueOf(numMiners[j]);
			for (int i = 0; i < numRaces.length; i++) {
				arguments[2] = String.valueOf(numRaces[i]); // numRaces = y;
				System.out.printf("%d,", numMiners[j]);
				System.out.printf("%d,", numRaces[i]);
				Test3MultiWithElgamal.main(arguments);
			}
		}
		
		
		
	}
}
