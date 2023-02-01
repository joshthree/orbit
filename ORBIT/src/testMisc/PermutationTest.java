package testMisc;

import java.util.Arrays;

import org.bouncycastle.pqc.math.linearalgebra.Permutation;


public class PermutationTest {

	public static void main(String[] args) {
		int[] base = new int[] {4, 3, 5, 2, 1, 7, 6, 0};
		int[] f = new int[] {2, 1, 4, 7, 5, 0, 3, 6};
		int[] g = new int[] {7, 4, 3, 2, 1, 0, 6, 5};
		int[] f2 = new int[] {7, 4, 2, 5, 1, 3, 0, 6};
	
		
		Permutation p0 = new Permutation(base);
		Permutation pF = new Permutation(f);
		Permutation pG = new Permutation(g);
		Permutation pF2 = new Permutation(f2);


		System.out.println(Arrays.toString(pF.computeInverse().getVector()));
		System.out.println(Arrays.toString(pF.computeInverse().rightMultiply(p0).getVector()));
		System.out.println(Arrays.toString(pF.computeInverse().rightMultiply(p0).rightMultiply(pG).getVector()));
											
		System.out.println(Arrays.toString(pF.computeInverse().rightMultiply(p0).rightMultiply(pG).getVector()));
		System.out.println(Arrays.toString(pF2.rightMultiply(pF.computeInverse().rightMultiply(p0).rightMultiply(pG)).getVector()));
		
	}

}
