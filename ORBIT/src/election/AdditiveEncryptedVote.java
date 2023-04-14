package election;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

import blah.Additive_Pub_Key;
import election.multiCipherSVHNw.SVHNwEncryptedVoteMulti;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface AdditiveEncryptedVote extends EncryptedVote {
	AdditiveEncryptedVote scalarMultiply(BigInteger toMultiply, Additive_Pub_Key electionKey);
	AdditiveEncryptedVote homomorphicAdd(AdditiveEncryptedVote otherVote, Additive_Pub_Key electionKey);
}
 