package blah;

import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.CryptoData.CryptoData;

public abstract class AdditiveCiphertext extends Ciphertext {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4850230256505173129L;
	
	
	public abstract AdditiveCiphertext negate(Additive_Pub_Key pub);
	public abstract BigInteger negateEphemeral(BigInteger ephemeral, Additive_Pub_Key pub);
	
	public abstract AdditiveCiphertext homomorphicAdd(AdditiveCiphertext toAdd, Additive_Pub_Key pub);
	public abstract BigInteger homomorphicAddEphemeral(BigInteger ephemeral1, BigInteger ephemeral2, Additive_Pub_Key pub);
	public abstract AdditiveCiphertext scalarAdd(BigInteger toAdd, Additive_Pub_Key pub);
	public abstract BigInteger scalarAddEphemeral(BigInteger toAdd, BigInteger ephemeral, Additive_Pub_Key pub);
	public static AdditiveCiphertext homomorphicSum(AdditiveCiphertext[] toAdd, Additive_Pub_Key pub) {
		AdditiveCiphertext sum = pub.getEmptyCiphertext();
		for(int i = 0; i < toAdd.length; i++) {
			
			sum.mutableAdd(toAdd[i], pub);
		}
		return sum;
	}
	public abstract AdditiveCiphertext scalarMultiply(BigInteger toMultiply, Additive_Pub_Key pub);
	public abstract BigInteger scalarMultiplyEphemeral(BigInteger toMultiply, BigInteger ephemeral, Additive_Pub_Key pub);
	protected abstract void mutableAdd(AdditiveCiphertext toAdd, Additive_Pub_Key pub);
	
	public abstract AdditiveCiphertext rerandomize(SecureRandom rand, Additive_Pub_Key pub);
	public abstract AdditiveCiphertext rerandomize(BigInteger ephemeral, Additive_Pub_Key pub);
	public abstract BigInteger homomorphicSumEphemeral(BigInteger[] ephemerals, Additive_Pub_Key pub);
	
	public abstract CryptoData[] getEncryptionProverData(BigInteger message, BigInteger ephemeral, SecureRandom rand, Additive_Pub_Key pub);
	public abstract CryptoData[] getEncryptionVerifierData(BigInteger message, Additive_Pub_Key pub);
	
	public abstract CryptoData[] getRerandomizationProverData(AdditiveCiphertext original, BigInteger ephemeral, SecureRandom rand, Additive_Pub_Key pub);
	public abstract CryptoData[] getRerandomizationVerifierData(AdditiveCiphertext original, Additive_Pub_Key pub);
}
