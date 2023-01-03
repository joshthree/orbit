package blah;

import java.math.BigInteger;
import java.util.Random;

import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface Additive_Pub_Key extends Pub_Key {
	byte[] getPublicKey();
	
	AdditiveCiphertext getEmptyCiphertext();
	AdditiveCiphertext encrypt(BigInteger m, Random rand);
	
	ZKPProtocol getZKPforProofOfEncryption();
	
	AdditiveCiphertext encrypt(BigInteger m, BigInteger r);
	
	BigInteger getOrder();
	
	BigInteger generateEphemeral(Random rand);

	BigInteger getG();

	CryptoData getZKEnvironment();
}
