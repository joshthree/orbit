package test;

public class Experiment1 {
	public static void main(String arg[]) {
		String[] arguments = new String[5];
		arguments[0] = "40";// numRaces = 4;
		arguments[1] = "4";// numCandidates = 4;
		arguments[2] = "100";// numVotes = 50;
		arguments[3] = "10";// miners = 10;
		arguments[4] = "15";// ringSize = 15;
		int[] numRaces = {1, 2, 5, 10, 15,20,25,30,35,39};
		for (int i = 0; i < numRaces.length; i++) {
			arguments[1] = String.valueOf(numRaces[i]); // numRaces = y;
			
			Test2_1MultiWithElgamal.main2(arguments);
		}
		
		System.out.println("next");
		
		for (int i = 0; i < numRaces.length; i++) {
			arguments[0] = String.valueOf(numRaces[i]); // numRaces = y;

			Test2_1.main2(arguments);
		}
		
	}
}
