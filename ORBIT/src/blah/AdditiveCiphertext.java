package blah;

import java.math.BigInteger;

import zero_knowledge_proofs.CryptoData.CryptoData;

public abstract class AdditiveCiphertext extends Ciphertext {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4850230256505173129L;
	
	
	
	public abstract AdditiveCiphertext homomorphicAdd(AdditiveCiphertext toAdd);
	public abstract AdditiveCiphertext scalarAdd(BigInteger toAdd);
	public static AdditiveCiphertext homomorphicSum(AdditiveCiphertext[] toAdd) {
		AdditiveCiphertext sum = ((Additive_Pub_Key)toAdd[0].getPub_Key()).getEmptyCiphertext();
		for(int i = 0; i < toAdd.length; i++) {
			
			sum.mutableAdd(toAdd[i]);
		}
		return sum;
	}
	public abstract AdditiveCiphertext scalarMultiply(BigInteger toMultiply);
	public abstract AdditiveCiphertext getEmptyEncryption();
	protected abstract void mutableAdd(AdditiveCiphertext toAdd);
	
	public abstract CryptoData getEncryptionProofData(BigInteger toAdd);
}
