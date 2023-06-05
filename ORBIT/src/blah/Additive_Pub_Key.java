package blah;

import java.math.BigInteger;
import java.security.SecureRandom;

import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface Additive_Pub_Key extends Pub_Key {
	byte[] getPublicKey();
	
	AdditiveCiphertext getEmptyCiphertext();
	AdditiveCiphertext encrypt(BigInteger m, SecureRandom rand);
	
	ZKPProtocol getZKPforProofOfEncryption();
	ZKPProtocol getZKPforRerandomization();
	
	AdditiveCiphertext encrypt(BigInteger m, BigInteger r);
	
	BigInteger getOrder();
	

	CryptoData getZKZeroEnvironment();

	BigInteger generateEphemeral(SecureRandom rand);
	
	Additive_Pub_Key combineKeys(Additive_Pub_Key otherKey);
	Additive_Pub_Key removeKey(Additive_Pub_Key otherKey);
	
	boolean isSharable();
}
