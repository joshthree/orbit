package transactions;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECPoint;

import blah.AdditiveCiphertext;
import blah.AdditiveElgamalPrivKey;
import blah.AdditiveElgamalPubKey;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;
import election.Election;
import zero_knowledge_proofs.CryptoData.CryptoData;

public interface BallotT extends VoterTransaction {

	Additive_Pub_Key getVoterPubKey();

	// Dummy ballot parts 2 and 3 can be done here.
	void adjustForPassword(Additive_Priv_Key minerKey, ObjectInputStream[] in, ObjectOutputStream[] out);

	boolean verifyTransaction(ProcessedBlockchain b);

	byte[] getVoterProofBytes();

	long getPosition();

	void setPosition(long position);

	AdditiveCiphertext getDummyFlag();

	ECPoint getKeyImage();

	byte[] getBytes();

	boolean minerProcessBallot(ProcessedBlockchain blockchain, AdditiveElgamalPrivKey minerPrivKey,
			AdditiveElgamalPubKey[] individualMinerKeys, ObjectInputStream[] in, ObjectOutputStream[] out,
			SecureRandom rand);

	CryptoData[] getSmallTableVerifierData(Election election, AdditiveElgamalPubKey minerKey, int i,
			ElectionTableRowInner[] orig, ElectionTableRowInner[][] originalTables);

	CryptoData[] getSmallTableProverData(SecureRandom rand, Election election, AdditiveElgamalPubKey minerKey, int i,
			ElectionTableRowInner[] orig, boolean swap, BigInteger compareRerandmize0, BigInteger compareRerandmize1,
			BigInteger[][][] raceRerandomizer, ElectionTableRowInner[][] sourceTable,
			BigInteger[] outputCipherRerandmize);

}