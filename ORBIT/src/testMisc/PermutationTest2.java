package testMisc;

import java.util.Arrays;

import org.bouncycastle.pqc.math.linearalgebra.Permutation;


public class PermutationTest2 {

	public static void main(String[] args) {
		
										//first index: F2(F1(L)).  Second is G.
										//second index is 
		long[][] ephemeralTrackersF = new long[2][8];
		long[][] totalEphemeralsF = new long[2][8];
		long[][] ephemeralTrackersG = new long[2][8];
		
		int[] f1 = new int[] {3, 0, 7, 5, 1, 4, 2, 6};
		int[] f2 = new int[] {6, 7, 2, 0, 5, 4, 1, 3};
		int[] g1 = new int[] {4, 1, 7, 5, 0, 6, 2, 3};
		int[] g2 = new int[] {7, 4, 2, 5, 1, 3, 0, 6};
		
		for(int i = 0; i < ephemeralTrackersF[0].length; i++) {
			ephemeralTrackersF[0][i] = (1 << i);
			ephemeralTrackersF[1][i] = (1 << (i + 1 * ephemeralTrackersF.length));
			ephemeralTrackersG[0][i] = (1 << (i + 2 * ephemeralTrackersF.length));
			ephemeralTrackersG[1][i] = (1 << (i + 3 * ephemeralTrackersF.length));
		}

		for(int i = 0; i < f1.length; i++) {
			totalEphemeralsF[0][i] = ephemeralTrackersF[0][f1[i]];
		}
		for(int i = 0; i < f2.length; i++) {
			totalEphemeralsF[1][i] += totalEphemeralsF[0][f2[i]];
		}
		
		

		System.out.println(Arrays.toString(f1));
		System.out.println(Arrays.toString(f2));
		System.out.println(Arrays.toString(g1));
		System.out.println(Arrays.toString(g2));

		
	}

}
