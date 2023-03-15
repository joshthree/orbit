package transactions;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import blah.AdditiveCiphertext;
import blah.AdditiveElgamalCiphertext;
import blah.AdditiveElgamalPrivKey;
import blah.AdditiveElgamalPubKey;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;
import election.Election;
import election.EncryptedVote;
import election.Race;
import election.singleCipherSVHNw.SVHNwEncryptedVote;
import test.MinerThread;
import zero_knowledge_proofs.ArraySizesDoNotMatchException;
import zero_knowledge_proofs.ECDummyBallot10bProver;
import zero_knowledge_proofs.ECDummyBallot10dProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsForAnyNumberProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ECSchnorrCombinations;
import zero_knowledge_proofs.MultipleTrueProofException;
import zero_knowledge_proofs.NoTrueProofException;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class BallotTransaction4 implements BallotT {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7088852042122442011L;
	//Hashed
	private SourceTransaction[] ringMembers;
	private EncryptedVote[] voterVotes;
	private Additive_Pub_Key voterKey;
	private AdditiveCiphertext blindedPasswordOrigDecrypted;
	private AdditiveCiphertext blindedPasswordGuessDecrypted;
	private AdditiveCiphertext encryptedOldKey;
	private AdditiveCiphertext origDummy2;
	private AdditiveCiphertext origPassword2;
	private AdditiveCiphertext passwordGuessCipher;
	private AdditiveCiphertext origPassword2Blinded;
	private AdditiveCiphertext passwordGuessCipherBlinded;
	private AdditiveCiphertext password;
	private transient ECPoint keyImage;
	private byte[] keyImageBytes;

	private long electionPos;
	private long electionID;

	//Not Hashed
	
	//government work
	private EncryptedVote[] countedVotes;
	private AdditiveCiphertext dummyFlag;
	private AdditiveCiphertext tableOmega;
	private ElectionTableRowInner[][] intermediateDummyTables;
	private CryptoData[][] dummyProofTranscripts;



	private long position = -1;
	private CryptoData[] voterProofs;
	private CryptoData[][] dummyTableRandomizeTranscript;
	private CryptoData[][] dummyTableDecryptTranscript;
	private AdditiveElgamalCiphertext[] dummyInputsRandomized;
	private AdditiveElgamalCiphertext[] dummyInputsDecrypted;
	private CryptoData[][] passwordTableRandomizeTranscript;
	private AdditiveElgamalCiphertext[] passwordInputsRandomized;
	private ElectionTableRowInner[][] intermediatePasswordTables;
	private CryptoData[][] passwordProofTranscripts;
	private CryptoData[][] passwordTableDecryptTranscript;
	private AdditiveElgamalCiphertext[] passwordInputsDecrypted;

	public BallotTransaction4(SourceTransaction[] ringMembers, int source, Additive_Priv_Key signingKey, Additive_Priv_Key newKey, BigInteger passwordGuess, BigInteger passwordDisplacement, ElectionTransaction electionTx, EncryptedVote[] votes, BigInteger passwordRandomization, SecureRandom rand){
		super();
		Election election = electionTx.getElection();
		electionPos = electionTx.getPosition();
		electionID = electionTx.getPosition();
		voterVotes = votes;
		this.ringMembers = ringMembers;

		//		//Testing encrypted vote rerandomization.
		//		BigInteger[] r = election.getRace(0).generateRerandimizationValues(rand);
		//		EncryptedVote rerandomized = votes[0].rerandomize(r, election.getRace(0).getPubKey());
		////		EncryptedVote rerandomized = new SVHNwEncryptedVote(((AdditiveCiphertext) votes[0].getCiphertext()).rerandomize(r[0], election.getRace(0).getPubKey()), null);
		//		System.out.println(java.util.Arrays.toString(r));
		//		CryptoData[] proverInputs1 = rerandomized.getProverDataRandomizationProof(votes[0], r, election.getRace(0).getPubKey(), rand);
		//		CryptoData[] proverInputs2 = rerandomized.getProverDataRandomizationProof(votes[1], null, election.getRace(1).getPubKey(), rand);
		//		CryptoData[] verifierInputs1 = rerandomized.getVerificationDataRandomizationProof(votes[0], election.getRace(0).getPubKey());
		//		CryptoData[] verifierInputs2 = rerandomized.getVerificationDataRandomizationProof(votes[1], election.getRace(1).getPubKey());
		//		CryptoData[] verifierPub = new CryptoData[2];
		//		CryptoData[] verifierEnv = new CryptoData[2];
		//		
		//		verifierPub[0] = verifierInputs1[0];
		//		verifierPub[1] = verifierInputs2[0];
		//		verifierEnv[0] = verifierInputs1[1];
		//		verifierEnv[1] = verifierInputs2[1];
		//		
		//		CryptoData[] verifierInputs = new CryptoData[] {new CryptoDataArray(verifierPub), new CryptoDataArray(verifierEnv)};
		//		
		//
		//		CryptoData[] proverPub = new CryptoData[2];
		//		CryptoData[] proverSec = new CryptoData[3];
		//		CryptoData[] proverEnv = new CryptoData[2];
		//		CryptoData[] simulatedChallenges = new CryptoData[] {new BigIntData(null), new BigIntData(election.getRace(1).getPubKey().generateEphemeral(rand))};
		//		
		//		proverPub[0] = proverInputs1[0];
		//		proverPub[1] = proverInputs2[0];
		//		proverSec[0] = proverInputs1[1];
		//		proverSec[1] = proverInputs2[1];
		//		proverSec[2] = new CryptoDataArray(simulatedChallenges);
		//		proverEnv[0] = proverInputs1[2];
		//		proverEnv[1] = proverInputs2[2];
		//		
		//		CryptoData[] proverInputs = new CryptoData[] {new CryptoDataArray(proverPub), new CryptoDataArray(proverSec), new CryptoDataArray(proverEnv)};
		//		
		//		ZKPProtocol weirdProof = new ZeroKnowledgeOrProver(new ZKPProtocol[] {votes[0].getRandomizationProof(election.getRace(0).getPubKey()), votes[1].getRandomizationProof(election.getRace(0).getPubKey())}, election.getRace(0).getPubKey().getOrder());
		//		
		//		try {
		//			CryptoData[] weirdTranscript = weirdProof.proveFiatShamir(proverInputs[0], proverInputs[1], proverInputs[2]);
		//			if(!weirdProof.verifyFiatShamir(proverInputs[0], weirdTranscript[0], weirdTranscript[1], proverInputs[2])) System.out.println("qrewdafd failed 1");
		//			else System.out.println("fdsafadsf success 1");
		//			if(!weirdProof.verifyFiatShamir(verifierInputs[0], weirdTranscript[0], weirdTranscript[1], verifierInputs[1])) System.out.println("erqfdsaff failed 2");
		//			else System.out.println("fadsfadsf  success 2");
		//		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
		//				| ArraySizesDoNotMatchException e1) {
		//			// TODO Auto-generated catch block
		//			e1.printStackTrace();
		//		}



		//Execute Dummy Ballot part 1
		//Step 1:
		voterKey = newKey.getPubKey();
		//Step 2:
		BigInteger sourceVoterPrivKey = signingKey.getPrivKey()[0];
		BigInteger oldKeyR = voterKey.generateEphemeral(rand);
		AdditiveElgamalPubKey minerKey = election.getMinerKey();
		Additive_Pub_Key fullPasswordKey = minerKey.combineKeys(voterKey);
		encryptedOldKey = fullPasswordKey.encrypt(sourceVoterPrivKey, oldKeyR);
		BigInteger passwordR = fullPasswordKey.generateEphemeral(rand);
		passwordGuessCipher = fullPasswordKey.encrypt(passwordGuess, passwordR);

		//Step 3:
		AdditiveCiphertext origDummy1 = ringMembers[source].getDummyFlag();

		BigInteger origDummyR1 = minerKey.generateEphemeral(rand);

		AdditiveCiphertext origPassword1 = ringMembers[source].getPasswordCiphertext();


		origDummy2 = origDummy1.rerandomize(origDummyR1, minerKey);
		Additive_Pub_Key origPassPub = minerKey.combineKeys(ringMembers[source].getVoterPubKey());
		BigInteger origPasswordR1 = origPassPub.generateEphemeral(rand);
		origPassword2 = origPassword1.rerandomize(origPasswordR1, origPassPub);

		//Step 4: in arguments

		//Step 5:

		//Step 6:
		MessageDigest fastHashDigest = null;
		Security.addProvider(new BouncyCastleProvider());
		try {
			fastHashDigest = MessageDigest.getInstance("Keccak-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();
		ECPoint h1 = curve.decodePoint(fullPasswordKey.getPublicKey());
		byte[] keyImageBaseHash = fastHashDigest.digest(ringMembers[source].getVoterPubKey().getPublicKey());
		ECPoint keyImageBase = g.multiply(new BigInteger(keyImageBaseHash).mod(minerKey.getOrder()));
		keyImage = keyImageBase.multiply(sourceVoterPrivKey.add(passwordGuess).mod(minerKey.getOrder()));
		keyImageBytes = keyImage.getEncoded(true);
		//TODO Should be direct Hash to Point, but this will do for now

		//Step 7:
		BigInteger passwordRandomizationGamma = fullPasswordKey.generateEphemeral(rand);
		origPassword2Blinded = origPassword2.scalarMultiply(passwordRandomizationGamma, origPassPub);
		passwordGuessCipherBlinded = passwordGuessCipher.scalarMultiply(passwordRandomizationGamma, fullPasswordKey);

		//Step 8:
		blindedPasswordOrigDecrypted = signingKey.decrypt(origPassword2Blinded);

		BigInteger passwordDisplacementR = minerKey.generateEphemeral(rand);
		AdditiveCiphertext passwordDisplacementCipher = fullPasswordKey.encrypt(passwordDisplacement, passwordDisplacementR);
		AdditiveCiphertext blindedPasswordWithFullKey = ((AdditiveElgamalPrivKey) newKey).addKey(blindedPasswordOrigDecrypted);

		this.password = passwordDisplacementCipher.homomorphicAdd(blindedPasswordWithFullKey, fullPasswordKey);

		//Step 9:
		blindedPasswordGuessDecrypted = newKey.decrypt(passwordGuessCipherBlinded);

		//Step 10:  Proofs
		ZKPProtocol fullProof = getVoterProof(ringMembers, minerKey);

		//Generate CryptoData for Proofs.
		CryptoData[] fullProofData = getVoterProverData(source, newKey, passwordGuess, passwordDisplacement,
				rand, sourceVoterPrivKey, oldKeyR, minerKey, fullPasswordKey, origDummyR1, origPasswordR1, curve, g, h1,
				passwordRandomizationGamma, passwordDisplacementR, passwordR);



		voterProofs = null;
		try {
			System.out.flush();
			voterProofs = fullProof.proveFiatShamir(fullProofData[0], fullProofData[1], fullProofData[2]);
			//			ByteArrayOutputStream out1 = new ByteArrayOutputStream();
			//			ObjectOutputStream out = new ObjectOutputStream(out1);
			//			out.writeObject(this);
			//			ByteArrayInputStream in1 = new ByteArrayInputStream(out1.toByteArray());
			//			ObjectInputStream in = new ObjectInputStream(in1);
			//			BallotTransaction same = (BallotTransaction) in.readObject();
			//			CryptoData[] verifierData = same.getVoterVerifierData(election);
			//			CryptoData[] verifierData = this.getVoterVerifierData(election);

			//			System.out.println(fullProofData[0]);
			//			System.out.println(verifierData[0]);
			//			if(fullProofData[0].equals(verifierData[0])) {
			//				System.out.println("equal 1");
			//			} else {
			//				System.out.println("not equal 1");
			//			}

			//			System.out.println(fullProofData[2]);
			//			System.out.println(verifierData[1]);
			//			if(fullProofData[2].equals(verifierData[1])) {
			//				System.out.println("equal 2");
			//			} else {
			//				System.out.println("not equal 2");
			//			}

			//			boolean verify = fullProof.verifyFiatShamir(verifierData[0], voterProofs[0], voterProofs[1], verifierData[1]); 
			//			boolean verify = fullProof.verifyFiatShamir(fullProofData[0], same.voterProofs[0], same.voterProofs[1], fullProofData[2]);
			//			System.out.println(verify);
		} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
				| ArraySizesDoNotMatchException e) {
			e.printStackTrace();
		}

	}

	private CryptoData[] getVoterProverData(int source, Additive_Priv_Key newKey,
			BigInteger password, BigInteger passwordDisplacement, SecureRandom rand, BigInteger sourceVoterPrivKey,
			BigInteger oldKeyR, AdditiveElgamalPubKey minerKey, Additive_Pub_Key fullPasswordKey,
			BigInteger origDummyR1, BigInteger origPasswordR1, ECCurve curve, ECPoint g, ECPoint h1,
			BigInteger passwordRandomizationGamma, BigInteger passwordDisplacementR, BigInteger passwordR) {
		CryptoData[] fullProofData = new CryptoData[3];//0 for public, 1 for secret, 2 for environment
		CryptoData[][] fullProofDataUnpacked = new CryptoData[3][];//0 for public, 1 for secret, 2 for environment
		fullProofDataUnpacked[0] = new CryptoData[5];
		fullProofDataUnpacked[1] = new CryptoData[5];
		fullProofDataUnpacked[2] = new CryptoData[6];
		CryptoData[][] proofOfMatchingData = new CryptoData[3][];
		proofOfMatchingData[0] = new CryptoData[ringMembers.length];
		proofOfMatchingData[1] = new CryptoData[ringMembers.length+1];
		proofOfMatchingData[2] = new CryptoData[ringMembers.length];
		CryptoData[] simulatedChallenges = new CryptoData[ringMembers.length];
		for(int i = 0; i < ringMembers.length; i++) {
			CryptoData[] innerFirstPub = new CryptoData[2];
			CryptoData[] innerFirstSec;

			CryptoData[] innerFirstEnv = new CryptoData[2];
			innerFirstEnv[0] = new ECCurveData(curve, h1);
			innerFirstEnv[1] = new ECPointData(g);
			if(i == source) {
				innerFirstSec = new CryptoData[2];
			} else {
				innerFirstSec = new CryptoData[1];
			}

			ECPoint signingPub = curve.decodePoint(ringMembers[i].getVoterPubKey().getPublicKey());
			{	
				Additive_Pub_Key origPassPubRing = minerKey.combineKeys(ringMembers[i].getVoterPubKey());
				CryptoData[] proofOfMatchingDataInner = new CryptoData[3];
				AdditiveElgamalCiphertext newCipher = (AdditiveElgamalCiphertext) encryptedOldKey.homomorphicAdd(new AdditiveElgamalCiphertext(signingPub, curve.getInfinity()).negate(origPassPubRing),origPassPubRing);
				innerFirstPub[0] = new ECPointData((ECPoint) newCipher.getCipher(origPassPubRing));
				innerFirstPub[1] = new ECPointData(newCipher.getEphemeral(origPassPubRing));
				CryptoData[] dummyInputs;
				CryptoData[] passwordInputs;

				AdditiveCiphertext sourceOrigDummy = ringMembers[i].getDummyFlag();
				ECPoint[] publicForKeyImageProof = new ECPoint[5];
				publicForKeyImageProof[0] = getKeyImage();
				publicForKeyImageProof[1] = (ECPoint) encryptedOldKey.getCipher(fullPasswordKey);
				publicForKeyImageProof[2] = ((AdditiveElgamalCiphertext) encryptedOldKey).getEphemeral(minerKey);
				publicForKeyImageProof[3] = (ECPoint) passwordGuessCipher.getCipher(minerKey);
				publicForKeyImageProof[4] = ((AdditiveElgamalCiphertext) passwordGuessCipher).getEphemeral(minerKey);

				BigInteger[] secretsForKeyImageProof;


				CryptoData[] envForKeyImageProof = new CryptoData[5];

				MessageDigest fastHashDigest = null;
				Security.addProvider(new BouncyCastleProvider());
				try {
					fastHashDigest = MessageDigest.getInstance("Keccak-256");
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				byte[] keyImageBaseHash = fastHashDigest.digest(ringMembers[i].getVoterPubKey().getPublicKey());
				//				System.out.printf("For ring member %d in tx:%s,  \n\t%s\n", i, ((AdditiveElgamalPubKey) voterKey).getY(), new BigInteger(keyImageBaseHash).mod(minerKey.getOrder()));

				ECPoint keyImageBase = g.multiply(new BigInteger(keyImageBaseHash).mod(minerKey.getOrder()));

				envForKeyImageProof[0] = new ECCurveData(curve, keyImageBase);
				envForKeyImageProof[1] = new ECPointData(g);
				envForKeyImageProof[2] = new ECPointData(h1);
				envForKeyImageProof[3] = new ECPointData(g);
				envForKeyImageProof[4] = new ECPointData(h1);

				innerFirstSec[0] = new BigIntData(minerKey.generateEphemeral(rand));
				if(i == source) {
					secretsForKeyImageProof = new BigInteger[8];
					innerFirstSec[1] = new BigIntData(oldKeyR);
					dummyInputs = origDummy2.getRerandomizationProverData(sourceOrigDummy, origDummyR1, rand, minerKey);
					passwordInputs = origPassword2.getRerandomizationProverData(ringMembers[i].getPasswordCiphertext(), origPasswordR1, rand, origPassPubRing);
					simulatedChallenges[i] = new BigIntData(null);
					secretsForKeyImageProof[4] = sourceVoterPrivKey;
					secretsForKeyImageProof[5] = password;
					secretsForKeyImageProof[6] = oldKeyR;
					secretsForKeyImageProof[7] = passwordR;
				} else {
					secretsForKeyImageProof = new BigInteger[4];
					dummyInputs = origDummy2.getRerandomizationProverData(sourceOrigDummy, null, rand, minerKey);					
					passwordInputs = origPassword2.getRerandomizationProverData(ringMembers[i].getPasswordCiphertext(), null, rand, origPassPubRing);
					simulatedChallenges[i] = new BigIntData(minerKey.generateEphemeral(rand));
				}

				for(int j = 0; j < 4; j++) {
					secretsForKeyImageProof[j] = minerKey.generateEphemeral(rand);
				}

				proofOfMatchingDataInner[0] = new CryptoDataArray(innerFirstPub);
				proofOfMatchingDataInner[1] = new CryptoDataArray(innerFirstSec);
				proofOfMatchingDataInner[2] = new CryptoDataArray(innerFirstEnv);
				proofOfMatchingData[0][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[0],
						dummyInputs[0],
						passwordInputs[0],
						new CryptoDataArray(publicForKeyImageProof)

				});

				proofOfMatchingData[1][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[1],
						dummyInputs[1],
						passwordInputs[1],
						new CryptoDataArray(secretsForKeyImageProof)
				});

				proofOfMatchingData[2][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[2],
						dummyInputs[2],
						passwordInputs[2],
						new CryptoDataArray(envForKeyImageProof)
				});
			}
		}
		proofOfMatchingData[1][proofOfMatchingData[1].length-1] = new CryptoDataArray(simulatedChallenges);
		fullProofDataUnpacked[0][0] = new CryptoDataArray(proofOfMatchingData[0]);
		fullProofDataUnpacked[1][0] = new CryptoDataArray(proofOfMatchingData[1]);
		fullProofDataUnpacked[2][0] = new CryptoDataArray(proofOfMatchingData[2]);




		ECPoint[] publicForPasswordBlinding = new ECPoint[4];

		publicForPasswordBlinding[0] = (ECPoint) origPassword2Blinded.getCipher(minerKey);
		publicForPasswordBlinding[1] = ((AdditiveElgamalCiphertext) origPassword2Blinded).getEphemeral(minerKey);
		publicForPasswordBlinding[2] = (ECPoint) passwordGuessCipherBlinded.getCipher(minerKey);
		publicForPasswordBlinding[3] = ((AdditiveElgamalCiphertext) passwordGuessCipherBlinded).getEphemeral(minerKey);

		BigInteger[] secretsForPasswordBlinding = new BigInteger[2];

		secretsForPasswordBlinding[0] = minerKey.generateEphemeral(rand);
		secretsForPasswordBlinding[1] = passwordRandomizationGamma;

		CryptoData[] envForPasswordBlinding = new CryptoData[4];

		envForPasswordBlinding[0] = new ECCurveData(curve, (ECPoint) origPassword2.getCipher(minerKey));
		envForPasswordBlinding[1] = new ECPointData(((AdditiveElgamalCiphertext) origPassword2).getEphemeral(minerKey));
		envForPasswordBlinding[2] = new ECPointData((ECPoint) passwordGuessCipher.getCipher(minerKey));
		envForPasswordBlinding[3] = new ECPointData(((AdditiveElgamalCiphertext) passwordGuessCipher).getEphemeral(minerKey));

		fullProofDataUnpacked[0][1] = new CryptoDataArray(publicForPasswordBlinding);
		fullProofDataUnpacked[1][1] = new CryptoDataArray(secretsForPasswordBlinding);
		fullProofDataUnpacked[2][1] = new CryptoDataArray(envForPasswordBlinding);

		ECPoint[] publicForOrigDecrypt = new ECPoint[3];

		AdditiveElgamalCiphertext diff1 = (AdditiveElgamalCiphertext) origPassword2Blinded.homomorphicAdd(blindedPasswordOrigDecrypted.negate(minerKey), minerKey);
		publicForOrigDecrypt[0] = (ECPoint) diff1.getCipher(minerKey);
		publicForOrigDecrypt[1] = (ECPoint) encryptedOldKey.getCipher(minerKey);
		publicForOrigDecrypt[2] = ((AdditiveElgamalCiphertext) encryptedOldKey).getEphemeral(minerKey);

		BigInteger[] secretsForOrigDecrypt = new BigInteger[4];

		for(int i = 0; i < 2; i++) {
			secretsForOrigDecrypt[i] = minerKey.generateEphemeral(rand);
		}
		secretsForOrigDecrypt[2] = sourceVoterPrivKey;
		secretsForOrigDecrypt[3] = oldKeyR;

		CryptoData[] envForOrigDecrypt = new CryptoData[3];

		envForOrigDecrypt[0] = new ECCurveData(curve, ((AdditiveElgamalCiphertext) origPassword2Blinded).getEphemeral(minerKey));
		envForOrigDecrypt[1] = new ECPointData(g);
		envForOrigDecrypt[2] = new ECPointData(((AdditiveElgamalPubKey) fullPasswordKey).getY());

		fullProofDataUnpacked[0][2] = new CryptoDataArray(publicForOrigDecrypt);
		fullProofDataUnpacked[1][2] = new CryptoDataArray(secretsForOrigDecrypt);
		fullProofDataUnpacked[2][2] = new CryptoDataArray(envForOrigDecrypt);
		//DONE WITH D, NOW DOING E

		ECPoint[] publicForGuessDecrypt = new ECPoint[2];

		AdditiveElgamalCiphertext diff2 = (AdditiveElgamalCiphertext) passwordGuessCipherBlinded.homomorphicAdd(blindedPasswordGuessDecrypted.negate(minerKey), minerKey);

		publicForGuessDecrypt[0] = (ECPoint) diff2.getCipher(minerKey);
		publicForGuessDecrypt[1] = ((AdditiveElgamalCiphertext) passwordGuessCipherBlinded).getEphemeral(minerKey);

		BigInteger[] secretsForGuessDecrypt = new BigInteger[2];

		secretsForGuessDecrypt[0] = minerKey.generateEphemeral(rand);
		secretsForGuessDecrypt[1] = passwordRandomizationGamma.multiply(passwordR).mod(curve.getOrder());

		CryptoData[] envForGuessDecrypt = new CryptoData[2];
		envForGuessDecrypt[0] = new ECCurveData(curve, curve.decodePoint(voterKey.getPublicKey()));
		envForGuessDecrypt[1] = new ECPointData(g);

		//		ByteArrayOutputStream out1 = new ByteArrayOutputStream();
		//		MessageDigest digest = null;
		//		try {
		//			digest = MessageDigest.getInstance("SHA-256");
		//		} catch (NoSuchAlgorithmException e) {
		//			e.printStackTrace();
		//		}
		BigInteger transactionHash = new BigInteger(getVoterProofBytes());
		fullProofDataUnpacked[0][3] = new CryptoDataArray(publicForGuessDecrypt);
		fullProofDataUnpacked[1][3] = new CryptoDataArray(secretsForGuessDecrypt);
		fullProofDataUnpacked[2][3] = new CryptoDataArray(envForGuessDecrypt);
		//		
		//  g = 0, h = 1, origEphemeral = 2
		//  k = 0, x = 1, r_2 = 2
		//		int[][][] structure = new int[][][] {{{2, 1},{0, 0},{1, 2}},{{0, 2}},{{0, 1}}};
		CryptoData[] pubForNewPassword = new CryptoData[3];
		AdditiveCiphertext oddCipher = this.password.homomorphicAdd(blindedPasswordOrigDecrypted.negate(minerKey), minerKey);
		pubForNewPassword[0] = new ECPointData((ECPoint) oddCipher.getCipher(minerKey));
		pubForNewPassword[1] = new ECPointData(((AdditiveElgamalCiphertext) oddCipher).getEphemeral(minerKey));
		pubForNewPassword[2] = new ECPointData(curve.decodePoint(voterKey.getPublicKey()));

		CryptoData[] secForNewPassword = new CryptoData[6];
		for(int i = 0; i < secForNewPassword.length/2; i++) {
			secForNewPassword[i] = new BigIntData(fullPasswordKey.generateEphemeral(rand));
		}
		secForNewPassword[0+secForNewPassword.length/2] = new BigIntData(passwordDisplacement);
		secForNewPassword[1+secForNewPassword.length/2] = new BigIntData(newKey.getPrivKey()[0]);
		secForNewPassword[2+secForNewPassword.length/2] = new BigIntData(passwordDisplacementR);

		CryptoData[] envForNewPassword = new CryptoData[3];

		envForNewPassword[0] = new ECCurveData(curve, g);
		envForNewPassword[1] = new ECPointData(h1);
		envForNewPassword[2] = new ECPointData(((AdditiveElgamalCiphertext) blindedPasswordOrigDecrypted).getEphemeral(minerKey));

		fullProofDataUnpacked[0][4] = new CryptoDataArray(pubForNewPassword);
		fullProofDataUnpacked[1][4] = new CryptoDataArray(secForNewPassword);
		fullProofDataUnpacked[2][4] = new CryptoDataArray(envForNewPassword);

		fullProofDataUnpacked[2][5] = new BigIntData(transactionHash);

		for(int i = 0; i < 3; i++) {
			fullProofData[i] = new CryptoDataArray(fullProofDataUnpacked[i]);
		}
		return fullProofData;
	}

	private CryptoData[] getVoterVerifierData(Election election) {

		AdditiveElgamalPubKey minerKey = election.getMinerKey();
		Additive_Pub_Key fullPasswordKey = minerKey.combineKeys(voterKey);

		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();
		ECPoint h1 = ((AdditiveElgamalPubKey) fullPasswordKey).getY();
		CryptoData[] fullProofData = new CryptoData[2];//0 for public, 1 for environment
		CryptoData[][] fullProofDataUnpacked = new CryptoData[2][];//0 for public, 1 for environment
		fullProofDataUnpacked[0] = new CryptoData[5];
		fullProofDataUnpacked[1] = new CryptoData[6];
		CryptoData[][] proofOfMatchingData = new CryptoData[2][];
		proofOfMatchingData[0] = new CryptoData[ringMembers.length];
		proofOfMatchingData[1] = new CryptoData[ringMembers.length];
		for(int i = 0; i < ringMembers.length; i++) {
			CryptoData[] innerFirstPub = new CryptoData[2];

			CryptoData[] innerFirstEnv = new CryptoData[2];
			innerFirstEnv[0] = new ECCurveData(curve, h1);
			innerFirstEnv[1] = new ECPointData(g);

			ECPoint signingPub = curve.decodePoint(ringMembers[i].getVoterPubKey().getPublicKey());
			{
				Additive_Pub_Key origPassPubRing = minerKey.combineKeys(ringMembers[i].getVoterPubKey());
				CryptoData[] proofOfMatchingDataInner = new CryptoData[3];
				AdditiveElgamalCiphertext newCipher = (AdditiveElgamalCiphertext) encryptedOldKey.homomorphicAdd(new AdditiveElgamalCiphertext(signingPub, curve.getInfinity()).negate(origPassPubRing),origPassPubRing);
				innerFirstPub[0] = new ECPointData((ECPoint) newCipher.getCipher(origPassPubRing));
				innerFirstPub[1] = new ECPointData(newCipher.getEphemeral(origPassPubRing));
				CryptoData[] dummyInputs;
				CryptoData[] passwordInputs;

				AdditiveCiphertext sourceOrigDummy = ringMembers[i].getDummyFlag();
				ECPoint[] publicForKeyImageProof = new ECPoint[5];
				publicForKeyImageProof[0] = getKeyImage();
				publicForKeyImageProof[1] = (ECPoint) encryptedOldKey.getCipher(fullPasswordKey);
				publicForKeyImageProof[2] = ((AdditiveElgamalCiphertext) encryptedOldKey).getEphemeral(minerKey);
				publicForKeyImageProof[3] = (ECPoint) passwordGuessCipher.getCipher(minerKey);
				publicForKeyImageProof[4] = ((AdditiveElgamalCiphertext) passwordGuessCipher).getEphemeral(minerKey);

				CryptoData[] envForKeyImageProof = new CryptoData[5];

				MessageDigest fastHashDigest = null;
				Security.addProvider(new BouncyCastleProvider());
				try {
					fastHashDigest = MessageDigest.getInstance("Keccak-256");
				} catch (NoSuchAlgorithmException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				byte[] keyImageBaseHash = fastHashDigest.digest(ringMembers[i].getVoterPubKey().getPublicKey());
				//				System.out.printf("For ring member %d in tx:%s,  \n\t%s\n", i, ((AdditiveElgamalPubKey) voterKey).getY(), new BigInteger(keyImageBaseHash).mod(minerKey.getOrder()));

				ECPoint keyImageBase = g.multiply(new BigInteger(keyImageBaseHash).mod(minerKey.getOrder()));

				envForKeyImageProof[0] = new ECCurveData(curve, keyImageBase);
				envForKeyImageProof[1] = envForKeyImageProof[3] = new ECPointData(g);
				envForKeyImageProof[2] = envForKeyImageProof[4] = new ECPointData(h1);

				dummyInputs = origDummy2.getRerandomizationVerifierData(sourceOrigDummy, minerKey);
				passwordInputs = origPassword2.getRerandomizationVerifierData(ringMembers[i].getPasswordCiphertext(), origPassPubRing);

				proofOfMatchingDataInner[0] = new CryptoDataArray(innerFirstPub);
				proofOfMatchingDataInner[1] = new CryptoDataArray(innerFirstEnv);
				proofOfMatchingData[0][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[0],
						dummyInputs[0],
						passwordInputs[0],
						new CryptoDataArray(publicForKeyImageProof)

				});

				proofOfMatchingData[1][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[1],
						dummyInputs[1],
						passwordInputs[1],
						new CryptoDataArray(envForKeyImageProof)
				});

			}
		}
		fullProofDataUnpacked[0][0] = new CryptoDataArray(proofOfMatchingData[0]);
		fullProofDataUnpacked[1][0] = new CryptoDataArray(proofOfMatchingData[1]);

		ECPoint[] publicForPasswordBlinding = new ECPoint[4];

		publicForPasswordBlinding[0] = (ECPoint) origPassword2Blinded.getCipher(minerKey);
		publicForPasswordBlinding[1] = ((AdditiveElgamalCiphertext) origPassword2Blinded).getEphemeral(minerKey);
		publicForPasswordBlinding[2] = (ECPoint) passwordGuessCipherBlinded.getCipher(minerKey);
		publicForPasswordBlinding[3] = ((AdditiveElgamalCiphertext) passwordGuessCipherBlinded).getEphemeral(minerKey);


		CryptoData[] envForPasswordBlinding = new CryptoData[4];

		envForPasswordBlinding[0] = new ECCurveData(curve, (ECPoint) origPassword2.getCipher(minerKey));
		envForPasswordBlinding[1] = new ECPointData(((AdditiveElgamalCiphertext) origPassword2).getEphemeral(minerKey));
		envForPasswordBlinding[2] = new ECPointData((ECPoint) passwordGuessCipher.getCipher(minerKey));
		envForPasswordBlinding[3] = new ECPointData(((AdditiveElgamalCiphertext) passwordGuessCipher).getEphemeral(minerKey));

		fullProofDataUnpacked[0][1] = new CryptoDataArray(publicForPasswordBlinding);
		fullProofDataUnpacked[1][1] = new CryptoDataArray(envForPasswordBlinding);

		ECPoint[] publicForOrigDecrypt = new ECPoint[3];

		AdditiveElgamalCiphertext diff1 = (AdditiveElgamalCiphertext) origPassword2Blinded.homomorphicAdd(blindedPasswordOrigDecrypted.negate(minerKey), minerKey);
		publicForOrigDecrypt[0] = (ECPoint) diff1.getCipher(minerKey);
		publicForOrigDecrypt[1] = (ECPoint) encryptedOldKey.getCipher(minerKey);
		publicForOrigDecrypt[2] = ((AdditiveElgamalCiphertext) encryptedOldKey).getEphemeral(minerKey);


		CryptoData[] envForOrigDecrypt = new CryptoData[3];

		envForOrigDecrypt[0] = new ECCurveData(curve, ((AdditiveElgamalCiphertext) origPassword2Blinded).getEphemeral(minerKey));
		envForOrigDecrypt[1] = new ECPointData(g);
		envForOrigDecrypt[2] = new ECPointData(((AdditiveElgamalPubKey) fullPasswordKey).getY());

		fullProofDataUnpacked[0][2] = new CryptoDataArray(publicForOrigDecrypt);
		fullProofDataUnpacked[1][2] = new CryptoDataArray(envForOrigDecrypt);

		//DONE WITH D, NOW DOING E

		ECPoint[] publicForGuessDecrypt = new ECPoint[2];

		AdditiveElgamalCiphertext diff2 = (AdditiveElgamalCiphertext) passwordGuessCipherBlinded.homomorphicAdd(blindedPasswordGuessDecrypted.negate(minerKey), minerKey);

		publicForGuessDecrypt[0] = (ECPoint) diff2.getCipher(minerKey);
		publicForGuessDecrypt[1] = ((AdditiveElgamalCiphertext) passwordGuessCipherBlinded).getEphemeral(minerKey);

		CryptoData[] envForGuessDecrypt = new CryptoData[2];
		envForGuessDecrypt[0] = new ECCurveData(curve, curve.decodePoint(voterKey.getPublicKey()));
		envForGuessDecrypt[1] = new ECPointData(g);

		//		ByteArrayOutputStream out1 = new ByteArrayOutputStream();
		//		MessageDigest digest = null;
		//		try {
		//			digest = MessageDigest.getInstance("SHA-256");
		//		} catch (NoSuchAlgorithmException e) {
		//			e.printStackTrace();
		//		}
		BigInteger transactionHash = new BigInteger(getVoterProofBytes());
		fullProofDataUnpacked[0][3] = new CryptoDataArray(publicForGuessDecrypt);
		fullProofDataUnpacked[1][3] = new CryptoDataArray(envForGuessDecrypt);
		//		
		//  g = 0, h = 1, origEphemeral = 2
		//  k = 0, x = 1, r_2 = 2
		//		int[][][] structure = new int[][][] {{{2, 1},{0, 0},{1, 2}},{{0, 2}},{{0, 1}}};
		CryptoData[] pubForNewPassword = new CryptoData[3];
		AdditiveCiphertext oddCipher = this.password.homomorphicAdd(blindedPasswordOrigDecrypted.negate(minerKey), minerKey);
		pubForNewPassword[0] = new ECPointData((ECPoint) oddCipher.getCipher(minerKey));
		pubForNewPassword[1] = new ECPointData(((AdditiveElgamalCiphertext) oddCipher).getEphemeral(minerKey));
		pubForNewPassword[2] = new ECPointData(curve.decodePoint(voterKey.getPublicKey()));


		CryptoData[] envForNewPassword = new CryptoData[3];

		envForNewPassword[0] = new ECCurveData(curve, g);
		envForNewPassword[1] = new ECPointData(h1);
		envForNewPassword[2] = new ECPointData(((AdditiveElgamalCiphertext) blindedPasswordOrigDecrypted).getEphemeral(minerKey));

		fullProofDataUnpacked[0][4] = new CryptoDataArray(pubForNewPassword);
		fullProofDataUnpacked[1][4] = new CryptoDataArray(envForNewPassword);

		fullProofDataUnpacked[1][5] = new BigIntData(transactionHash);

		for(int i = 0; i < 2; i++) {
			fullProofData[i] = new CryptoDataArray(fullProofDataUnpacked[i]);
		}
		return fullProofData;
	}

	private ZKPProtocol getVoterProof(SourceTransaction[] ringMembers, AdditiveElgamalPubKey minerKey) {
		ZKPProtocol[] validTransactionInner = new ZKPProtocol[5];

		//Create proof for one transaction on step 10a
		ZKPProtocol[] proofOfMatchingInner = new ZKPProtocol[4];
		//Proof of first bulletpoint is essentially cipher - key is a DHH with ephemeral
		//Proof of second and third bullet points are proofs of rerandomization:  cipher1 - cipher2, then DHH
		proofOfMatchingInner[0] = proofOfMatchingInner[1] = proofOfMatchingInner[2] = minerKey.getZKPforRerandomization();
		proofOfMatchingInner[3] = new ECDummyBallot10bProver();

		ZKPProtocol proofOfMatching = new ZeroKnowledgeAndProver(proofOfMatchingInner);

		ZKPProtocol[] ringPortionInner = new ZKPProtocol[ringMembers.length];
		for(int i = 0; i < ringPortionInner.length; i++) {
			ringPortionInner[i] = proofOfMatching;
		}
		//Create proof for step b
		validTransactionInner[0] = new ZeroKnowledgeOrProver(ringPortionInner, minerKey.getOrder());

		//Create proof for step c
		validTransactionInner[1] = new ECEqualDiscreteLogsForAnyNumberProver(4);
		//Create proof for step d:
		validTransactionInner[2] = new ECDummyBallot10dProver();
		//Create proof for step e:
		//		validTransactionInner[4] = new ECEqualDiscreteLogsForAnyNumberProver(2);
		validTransactionInner[3] = new ECSchnorrCombinations(new int[][][] {{{0, 0}},{{1, 0}}});
		//  g = 0, h = 1, origEphemeral = 2
		//  k = 0, x = 1, r_2 = 2
		int[][][] structure = new int[][][] {{{2, 1},{0, 0},{1, 2}},{{0, 2}},{{0, 1}}};
		validTransactionInner[4] = new ECSchnorrCombinations(structure);
		ZKPProtocol fullProof = new ZeroKnowledgeAndProver(validTransactionInner);
		return fullProof;
	}

	@Override
	public AdditiveCiphertext getPasswordCiphertext() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Additive_Pub_Key getVoterPubKey() {
		// TODO Auto-generated method stub
		return null;
	}

	// Dummy ballot parts 2 and 3 can be done here.
	@Override
	public void adjustForPassword(Additive_Priv_Key minerKey, ObjectInputStream[] in, ObjectOutputStream[] out) {

	}



	@Override
	public boolean verifyTransaction(ProcessedBlockchain b) {
		try {
			ElectionTransaction electionTx = (ElectionTransaction) b.getTransaction((int) electionPos);
			Election e = electionTx.getElection();
			CryptoData[] verifierData = getVoterVerifierData(e);
			ZKPProtocol proof = this.getVoterProof(ringMembers, e.getMinerKey());
			if(!proof.verifyFiatShamir(verifierData[0], voterProofs[0], voterProofs[1], verifierData[1])) {
				System.out.println("Voter Transaction Proof Failed");
				return false;
			}
			if(!e.verify(voterVotes)) {
				System.out.println("Encrypted Votes Proof Failed");
				return false;
			}
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public byte[] getVoterProofBytes(){
		byte[][] objectBytes = new byte[14][]; 
		byte[][] ringMemberBytes = new byte[ringMembers.length][];
		for(int i = 0; i < ringMembers.length; i++) {
			ringMemberBytes[i] = ringMembers[i].getBytes();
		}
		objectBytes[0] = Arrays.concatenate(ringMemberBytes);

		byte[][] encryptedVotesBytes = new byte[voterVotes.length][];
		for(int i = 0; i < voterVotes.length; i++) {
			encryptedVotesBytes[i] = voterVotes[i].getBytes();
		}
		objectBytes[1] = Arrays.concatenate(encryptedVotesBytes);
		objectBytes[2] = voterKey.getBytes();
		objectBytes[3] = blindedPasswordOrigDecrypted.getBytes();
		objectBytes[4] = blindedPasswordGuessDecrypted.getBytes();
		objectBytes[5] = encryptedOldKey.getBytes();
		objectBytes[6] = origDummy2.getBytes();
		objectBytes[7] = origPassword2.getBytes();
		objectBytes[8] = passwordGuessCipher.getBytes();
		objectBytes[9] = origPassword2Blinded.getBytes();
		objectBytes[10] = passwordGuessCipherBlinded.getBytes();
		objectBytes[11] = password.getBytes();
		objectBytes[12] = keyImageBytes;
		objectBytes[13] = ByteBuffer.wrap(new byte[8]).putLong(electionID).array();
		return Arrays.concatenate(objectBytes);
		/*
		 * 
	private Additive_Pub_Key voterKey;
	private AdditiveCiphertext blindedPasswordOrigDecrypted;
	private AdditiveCiphertext blindedPasswordGuessDecrypted;
	private AdditiveCiphertext encryptedOldKey;
	private AdditiveCiphertext origDummy2;
	private AdditiveCiphertext origPassword2;
	private AdditiveCiphertext passwordGuessCipher;
	private AdditiveCiphertext origPassword2Blinded;
	private AdditiveCiphertext passwordGuessCipherBlinded;
	private AdditiveCiphertext password;
	private transient ECPoint keyImage;
	private byte[] keyImageBytes;

	private long electionID;
		 */
	}


	@Override
	public long getPosition() {
		return position;
	}



	@Override
	public void setPosition(long position) {
		this.position = position;
	}



	@Override
	public AdditiveCiphertext getDummyFlag() {
		// TODO Auto-generated method stub
		return dummyFlag;
	}
	@Override
	public ECPoint getKeyImage() {
		if(keyImage == null) keyImage = ((AdditiveElgamalPubKey) voterKey).getCurve().decodePoint(keyImageBytes);
		return keyImage;
	}


	@Override
	public byte[] getBytes() {
		// TODO Auto-generated method stub
		return ByteBuffer.wrap(new byte[8]).putLong(position).array();
	}

	@Override
	public boolean minerProcessBallot(ProcessedBlockchain blockchain, AdditiveElgamalPrivKey minerPrivKey, AdditiveElgamalPubKey[] individualMinerKeys, ObjectInputStream[] in, ObjectOutputStream[] out, SecureRandom rand) {
		int party = -1;
		
		Election election = ((ElectionTransaction) blockchain.getTransaction((int) electionPos)).getElection();
		AdditiveElgamalPubKey minerKey = election.getMinerKey();
		AdditiveElgamalCiphertext passwordDifferenceCipher = (AdditiveElgamalCiphertext) this.blindedPasswordOrigDecrypted.homomorphicAdd(this.blindedPasswordGuessDecrypted.negate(minerKey), voterKey);

		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();

		int rowCount = election.getRowCount();
		int abbridgedRowCount = election.getAbbridgedRowCount();
		boolean retry = false;
		do {
			tableOmega = null;
			retry = false;
			AdditiveCiphertext[] table1 = randomBits(abbridgedRowCount-1, minerKey, rand, out, in);
			AdditiveCiphertext[][] table3 = new AdditiveElgamalCiphertext[election.getAbbridgedRowCount()][3];
			for(int i = 0; i < abbridgedRowCount-1; i++) {
				table3[i][0] = minerKey.encrypt(BigInteger.valueOf(i+1), BigInteger.ZERO).homomorphicAdd(table1[i], minerKey);
				table3[i][1] = minerKey.encrypt(BigInteger.valueOf(i+1), BigInteger.ZERO);
				table3[i][2] = minerKey.encrypt(BigInteger.ZERO, BigInteger.ZERO);
			}
			table3[abbridgedRowCount-1][0] = passwordDifferenceCipher;
			table3[abbridgedRowCount-1][1] = minerKey.encrypt(BigInteger.ZERO, BigInteger.ZERO);
			table3[abbridgedRowCount-1][2] = minerKey.encrypt(BigInteger.ONE, BigInteger.ZERO);

			AdditiveCiphertext[][] table4 = shuffleInternal(table3, in, out, minerKey, rand);

			if(table4 == null) return false;

			ZKPProtocol proofOfStuff = new ECEqualDiscreteLogsProver();
			tableOmega = passwordDifferenceCipher;
			int countEqual = 0;
			int countUnequal = 0;
			for(int i = 0; i < table4.length; i++) {
				AdditiveElgamalCiphertext testOrig = (AdditiveElgamalCiphertext) table4[i][0].homomorphicAdd(table4[i][1].negate(minerKey), minerKey);
				int[] order = MinerThread.chooseOrder(in, out, minerKey, rand);
				AdditiveElgamalCiphertext test = testOrig;

				for(int j = 0; j < in.length; j++) {//randomize ciphertext
					if(in[order[j]] == null) { //my turn
						party = order[j];
						BigInteger toScalarMultiply = minerKey.generateEphemeral(rand);
						AdditiveElgamalCiphertext testNew = (AdditiveElgamalCiphertext) test.scalarMultiply(toScalarMultiply, minerKey);

						for(int k = 0; k < in.length; k++) {
							if(out[k] == null) continue;
							try {
								out[k].writeObject(testNew);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}

						CryptoData[] proverInputs;
						proverInputs = new CryptoData[3];
						proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData((ECPoint) testNew.getCipher(minerKey)), new ECPointData(testNew.getEphemeral(minerKey))});
						proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(toScalarMultiply)});
						proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, (ECPoint) test.getCipher(minerKey)), new ECPointData(test.getEphemeral(minerKey))});

						CryptoData[] transcript = null;
						try {
							transcript = proofOfStuff.proveFiatShamir(proverInputs[0], proverInputs[1], proverInputs[2]);
						} catch (ClassNotFoundException | IOException | MultipleTrueProofException
								| NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						for(int k = 0; k < in.length; k++) {
							if(out[k] == null) continue;
							try {
								out[k].writeObject(transcript);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						
						for(int k = 0; k < in.length; k++) {
							if(out[k] == null) continue;
							try {
								out[k].flush();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						
						test = testNew;
					} else {//someone else's turn
						try {
							AdditiveElgamalCiphertext testNew = (AdditiveElgamalCiphertext) in[order[j]].readObject();
							CryptoData[] transcript = (CryptoData[]) in[order[j]].readObject();

							CryptoData[] verifierInputs;
							verifierInputs = new CryptoData[2];
							verifierInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData((ECPoint) testNew.getCipher(minerKey)), new ECPointData(testNew.getEphemeral(minerKey))});
							verifierInputs[1] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, (ECPoint) test.getCipher(minerKey)), new ECPointData(test.getEphemeral(minerKey))});
							if(!proofOfStuff.verifyFiatShamir(verifierInputs[0], transcript[0], transcript[1], verifierInputs[1])) {
								System.out.println("Error in randomization");
								return false;
							}
							test = testNew;
						} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							return false;
						}
					}
				}
				order = MinerThread.chooseOrder(in, out, minerKey, rand);
				for(int j = 0; j < in.length; j++) {//decrypt
					if(in[order[j]] == null) { //my turn
						AdditiveElgamalCiphertext testDec = (AdditiveElgamalCiphertext) minerPrivKey.decrypt(test);

						for(int k = 0; k < in.length; k++) {
							if(out[k] == null) continue;
							try {
								out[k].writeObject(testDec);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}

						CryptoData[] proverInputs;
						proverInputs = new CryptoData[3];
						proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(individualMinerKeys[order[j]].getY()), new ECPointData((ECPoint) ((AdditiveElgamalCiphertext) test.homomorphicAdd(testDec.negate(minerKey), minerKey)).getCipher(minerKey))});
						proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(minerPrivKey.getPrivKey()[0])});
						proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(test.getEphemeral(minerKey))});
						CryptoData[] transcript = null;
						try {
							transcript = proofOfStuff.proveFiatShamir(proverInputs[0], proverInputs[1], proverInputs[2]);
						} catch (ClassNotFoundException | IOException | MultipleTrueProofException
								| NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}

						for(int k = 0; k < in.length; k++) {
							if(out[k] == null) continue;
							try {
								out[k].writeObject(transcript);
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						for(int k = 0; k < in.length; k++) {
							if(out[k] == null) continue;
							try {
								out[k].flush();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
						test = testDec;
					} else {//someone else's turn
						try {
							AdditiveElgamalCiphertext testDec = (AdditiveElgamalCiphertext) in[order[j]].readObject();
							CryptoData[] transcript = (CryptoData[]) in[order[j]].readObject();

							CryptoData[] verifierInputs;
							verifierInputs = new CryptoData[2];
							verifierInputs[0] =  new CryptoDataArray(new CryptoData[] {new ECPointData(individualMinerKeys[order[j]].getY()), new ECPointData((ECPoint) ((AdditiveElgamalCiphertext) test.homomorphicAdd(testDec.negate(minerKey), minerKey)).getCipher(minerKey))});
							verifierInputs[1] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(test.getEphemeral(minerKey))});
							if(!proofOfStuff.verifyFiatShamir(verifierInputs[0], transcript[0], transcript[1], verifierInputs[1])) {
								System.out.println("Error in decrypt");
								return false;
							}
							test = testDec;
						} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
							return false;
						}
					}
				}
				if(curve.getInfinity().equals(test.getCipher(minerKey))) {
					tableOmega = tableOmega.homomorphicAdd(table4[i][2], minerKey);
					countEqual++;
				}else {
					countUnequal++;
				}
				if(i == election.getResetRowCount()) {
					if(countEqual == i || countUnequal == i) {
						retry = true;
						if(in[0] == null) {
							System.out.print("reshuffle required");
							}
						break;
					}
				}
			}
			if(retry) continue;
			//			AdditiveCiphertext test = sum;
			//			int[] order = MinerThread.chooseOrder(in, out, minerKey, rand);
			//			for(int j = 0; j < in.length; j++) {//decrypt
			//				if(in[order[j]] == null) { //my turn
			//					AdditiveElgamalCiphertext testDec = (AdditiveElgamalCiphertext) minerPrivKey.decrypt(test);
			//
			//					for(int k = 0; k < in.length; k++) {
			//						if(out[k] == null) continue;
			//						try {
			//							out[k].writeObject(testDec);
			//						} catch (IOException e) {
			//							// TODO Auto-generated catch block
			//							e.printStackTrace();
			//						}
			//					}
			//					
			//					CryptoData[] proverInputs;
			//					proverInputs = new CryptoData[3];
			//					proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(individualMinerKeys[order[j]].getY()), new ECPointData((ECPoint) ((AdditiveElgamalCiphertext) test.homomorphicAdd(testDec.negate(minerKey), minerKey)).getCipher(minerKey))});
			//					proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(minerPrivKey.getPrivKey()[0])});
			//					proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(((AdditiveElgamalCiphertext) test).getEphemeral(minerKey))});
			//					CryptoData[] transcript = null;
			//					try {
			//						transcript = proofOfStuff.proveFiatShamir(proverInputs[0], proverInputs[1], proverInputs[2]);
			//					} catch (ClassNotFoundException | IOException | MultipleTrueProofException
			//							| NoTrueProofException | ArraySizesDoNotMatchException e) {
			//						// TODO Auto-generated catch block
			//						e.printStackTrace();
			//					}
			//					
			//					for(int k = 0; k < in.length; k++) {
			//						if(out[k] == null) continue;
			//						try {
			//							out[k].writeObject(transcript);
			//						} catch (IOException e) {
			//							// TODO Auto-generated catch block
			//							e.printStackTrace();
			//						}
			//					}
			//					for(int k = 0; k < in.length; k++) {
			//						if(out[k] == null) continue;
			//						try {
			//							out[k].flush();
			//						} catch (IOException e) {
			//							// TODO Auto-generated catch block
			//							e.printStackTrace();
			//						}
			//					}
			//					test = testDec;
			//				} else {//someone else's turn
			//					try {
			//						AdditiveElgamalCiphertext testDec = (AdditiveElgamalCiphertext) in[order[j]].readObject();
			//						CryptoData[] transcript = (CryptoData[]) in[order[j]].readObject();
			//						
			//						CryptoData[] verifierInputs;
			//						verifierInputs = new CryptoData[2];
			//						verifierInputs[0] =  new CryptoDataArray(new CryptoData[] {new ECPointData(individualMinerKeys[order[j]].getY()), new ECPointData((ECPoint) ((AdditiveElgamalCiphertext) test.homomorphicAdd(testDec.negate(minerKey), minerKey)).getCipher(minerKey))});
			//						verifierInputs[1] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(((AdditiveElgamalCiphertext) test).getEphemeral(minerKey))});
			//						if(!proofOfStuff.verifyFiatShamir(verifierInputs[0], transcript[0], transcript[1], verifierInputs[1])) {
			//							System.out.println("Error in decrypt");
			//							return false;
			//						}
			//						test = testDec;
			//					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
			//						// TODO Auto-generated catch block
			//						e.printStackTrace();
			//						return false;
			//					}
			//				}
			//			}
			//			if(test.getCipher(minerKey).equals(g)) {
			//				System.out.printf("Good password: %s == %n\n", test.getCipher(minerKey), g);
			//			} else {
			//				System.out.printf("Bad password: %s != %s\n", test.getCipher(minerKey), g);
			//			}
		} while(retry);

		EncryptedVote[] zeroVote = new EncryptedVote[voterVotes.length];
		EncryptedVote[] voterVoteWithoutProof = new EncryptedVote[voterVotes.length];
		for(int i = 0; i < voterVotes.length; i++) {
			zeroVote[i] = election.getRace(i).zeroVote(voterVotes[i]);
			voterVoteWithoutProof[i] = voterVotes[i].withoutProof();
		}
		{
			ZKPProtocol ballotTableProof;
			ZKPProtocol[] proofArray = new ZKPProtocol[2];
			ZKPProtocol[] midProof = new ZKPProtocol[2];
			ZKPProtocol[] midProof2 = new ZKPProtocol[2];
			midProof2[0] = midProof2[1] = minerKey.getZKPforRerandomization();
			midProof[0] = new ZeroKnowledgeAndProver(midProof2);
			midProof[1] = midProof[0];
			proofArray[0] = proofArray[1] = new ZeroKnowledgeAndProver(midProof);
			ballotTableProof = new ZeroKnowledgeOrProver(proofArray, minerKey.getOrder());

			
			intermediateDummyTables = new ElectionTableRowInner[in.length][];
			dummyProofTranscripts = new CryptoData[in.length][];
			ElectionTableRowInner[] dummyTable0 = new ElectionTableRowInner[2];		
			dummyTable0[0] = new ElectionTableRowInner(minerKey.encrypt(BigInteger.ZERO, BigInteger.ZERO), null, passwordDifferenceCipher);
			dummyTable0[1] = new ElectionTableRowInner(minerKey.encrypt(BigInteger.ONE, BigInteger.ZERO), null, tableOmega);
			int[] order = MinerThread.chooseOrder(in, out, minerKey, rand);
			for(int i = 0; i < in.length; i++) {
				ElectionTableRowInner[] orig;
				if(i == 0) orig = dummyTable0;
				else orig = intermediateDummyTables[i-1];
				if(in[order[i]] == null) { //my turn
					//decide whether to shuffle
					CryptoData[] proverInputs = new CryptoData[3];
					boolean swap = rand.nextBoolean();

					intermediateDummyTables[i] = new ElectionTableRowInner[2];
					BigInteger compareRerandmize0 = minerKey.generateEphemeral(rand);
					BigInteger compareRerandmize1 = minerKey.generateEphemeral(rand);
					BigInteger[] diffRerandomizer = new BigInteger[2];
					diffRerandomizer[0] = minerKey.generateEphemeral(rand);
					diffRerandomizer[1] = minerKey.generateEphemeral(rand);
					if(swap) {
						intermediateDummyTables[i][0] = orig[1].rerandomize(compareRerandmize0, null, diffRerandomizer[0], election);
						intermediateDummyTables[i][1] = orig[0].rerandomize(compareRerandmize1, null, diffRerandomizer[1], election);
					} else {
						intermediateDummyTables[i][0] = orig[0].rerandomize(compareRerandmize0, null, diffRerandomizer[0], election);
						intermediateDummyTables[i][1] = orig[1].rerandomize(compareRerandmize1, null, diffRerandomizer[1], election);
					}
					for(int j = 0; j < in.length; j++) {
						if(out[j] != null) {
							try {
								out[j].writeObject(intermediateDummyTables[i]);
								out[j].flush();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
					}
					CryptoData[] fullProofData = getSmallTableProverData(rand, election, minerKey, i, orig, swap,
							compareRerandmize0, compareRerandmize1, null, intermediateDummyTables, diffRerandomizer);

					try {
						dummyProofTranscripts[i] = ballotTableProof.proveFiatShamir(fullProofData[0], fullProofData[1], fullProofData[2]);
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					for(int j = 0; j < in.length; j++) {
						if(out[j] != null) {
							try {
								out[j].writeObject(dummyProofTranscripts[i]);
								out[j].flush();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
					}
				} else {
					//Other turn
					//decide whether to shuffle
					try {
						intermediateDummyTables[i] = (ElectionTableRowInner[]) in[order[i]].readObject();
					} catch (ClassNotFoundException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					CryptoData[] fullProofData = getSmallTableVerifierData(election, minerKey, i, orig, intermediateDummyTables);
					try {
						dummyProofTranscripts[i] = (CryptoData[]) in[order[i]].readObject();
						if(!ballotTableProof.verifyFiatShamir(fullProofData[0], dummyProofTranscripts[i][0], dummyProofTranscripts[i][1], fullProofData[1])) {
							System.out.println("Failed Dummy Ballot Proof");
						}
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

				}

			}
		}
		//PET on small table
		{
			dummyTableRandomizeTranscript = new CryptoData[2][2];
			ZKPProtocol proofOfStuff = new ECEqualDiscreteLogsProver();
			ECPoint[][] combinedA = new ECPoint[2][2];
			BigInteger[] combinedZ = new BigInteger[2];
			
			//first, randomize.  Then prove.
			BigInteger[] toScalarMultiply = new BigInteger[] {minerKey.generateEphemeral(rand), minerKey.generateEphemeral(rand)};
			dummyInputsRandomized = new AdditiveElgamalCiphertext[2];
			for(int i = 0; i < 2; i++) {
				dummyInputsRandomized[i] = (AdditiveElgamalCiphertext) intermediateDummyTables[in.length-1][i].compare.scalarMultiply(toScalarMultiply[i], minerKey);

			}
			for(int k = 0; k < in.length; k++) {
				if(out[k] == null) continue;
				try {
					out[k].writeObject(dummyInputsRandomized);
					out[k].flush();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			for(int k = 0; k < in.length; k++) {
				if(in[k] == null) continue;
				try {
					AdditiveCiphertext[] other = (AdditiveCiphertext[]) in[k].readObject();
					for(int i = 0; i < 2; i++) {
						dummyInputsRandomized[i] = (AdditiveElgamalCiphertext) dummyInputsRandomized[i].homomorphicAdd(other[i], minerKey);
					}
				} catch (IOException | ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			for(int i = 0; i < 2; i++) {

				AdditiveElgamalCiphertext test = (AdditiveElgamalCiphertext) intermediateDummyTables[in.length - 1][i].compare;

				CryptoData[] proverInputs = new CryptoData[3];
				proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData((ECPoint) dummyInputsRandomized[i].getCipher(minerKey)), new ECPointData(dummyInputsRandomized[i].getEphemeral(minerKey))});
				proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(toScalarMultiply[i])});
				proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, (ECPoint) test.getCipher(minerKey)), new ECPointData(test.getEphemeral(minerKey))});
				CryptoData a = null;
				try {
					a = proofOfStuff.initialComm(proverInputs[0], proverInputs[1], proverInputs[2]);
					CryptoData[] aUnpacked = a.getCryptoDataArray();
					combinedA[i][0] = aUnpacked[0].getECPointData(curve);
					combinedA[i][1] = aUnpacked[1].getECPointData(curve);
				} catch (MultipleTrueProofException	| NoTrueProofException | ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				for(int k = 0; k < in.length; k++) {
					if(out[k] == null) continue;
					try {
						out[k].writeObject(a);
						out[k].flush();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				for(int k = 0; k < in.length; k++) {
					if(in[k] == null) continue;
					try {
						a = (CryptoData) in[k].readObject();
						CryptoData[] aUnpacked = a.getCryptoDataArray();
						combinedA[i][0] = combinedA[i][0].add(aUnpacked[0].getECPointData(curve));
						combinedA[i][1] = combinedA[i][1].add(aUnpacked[1].getECPointData(curve));
					} catch (IOException | ClassNotFoundException e) {
						e.printStackTrace();
					}
				}
				dummyTableRandomizeTranscript[i][0] = new CryptoDataArray(combinedA[i]);
				BigInteger challenge = proofOfStuff.fiatShamirChallange(proverInputs[0], dummyTableRandomizeTranscript[i][0], proverInputs[2]);
				try {
					CryptoData z = proofOfStuff.calcResponse(proverInputs[0], proverInputs[1], challenge, proverInputs[2]);
					combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().mod(curve.getOrder());
					for(int k = 0; k < in.length; k++) {
						if(out[k] == null) continue;
						try {
							out[k].writeObject(z);
							out[k].flush();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
					for(int k = 0; k < in.length; k++) {
						if(in[k] == null) continue;
						try {
							z = (CryptoData) in[k].readObject();
							combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().add(combinedZ[i]).mod(curve.getOrder());
						} catch (IOException | ClassNotFoundException e) {
							e.printStackTrace();
						}
					}
				} catch (NoTrueProofException | MultipleTrueProofException e) {
					e.printStackTrace();
				}
					
				dummyTableRandomizeTranscript[i][1] = new CryptoDataArray(new BigInteger[] {combinedZ[i]});
				try {
					if(proofOfStuff.verifyFiatShamir(proverInputs[0], dummyTableRandomizeTranscript[i][0], dummyTableRandomizeTranscript[i][1], proverInputs[2])) {
						
					} else {
						System.out.println("The dream is deaed :-( -1");
					}
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

			}
			
			

			dummyTableDecryptTranscript = new CryptoData[2][2];
			combinedA = new ECPoint[2][2];
			combinedZ = new BigInteger[2];
			
			//first, decrypt.  Then prove.
			toScalarMultiply = new BigInteger[] {minerKey.generateEphemeral(rand), minerKey.generateEphemeral(rand)};
			ECPoint[] testDec = new ECPoint[2];
			for(int i = 0; i < 2; i++) {
				testDec[i] = dummyInputsRandomized[i].getEphemeral(minerKey).multiply(minerPrivKey.getPrivKey()[0]);

			}
			for(int k = 0; k < in.length; k++) {
				if(out[k] == null) continue;
				try {
					out[k].writeObject(testDec[0].getEncoded(true));
					out[k].writeObject(testDec[1].getEncoded(true));
					out[k].flush();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			ECPoint[] other = new ECPoint[2];
			for(int k = 0; k < in.length; k++) {
				if(in[k] == null) continue;
				try {
					other[0] = curve.decodePoint((byte[]) in[k].readObject());
					other[1] = curve.decodePoint((byte[]) in[k].readObject());
					for(int i = 0; i < 2; i++) {
						testDec[i] = testDec[i].add(other[i]);
					}
				} catch (IOException | ClassNotFoundException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			dummyInputsDecrypted = new AdditiveElgamalCiphertext[2];
			for(int i = 0; i < 2; i++) {
				AdditiveElgamalCiphertext test = dummyInputsRandomized[i];
				dummyInputsDecrypted[i] = (AdditiveElgamalCiphertext) test.homomorphicAdd(new AdditiveElgamalCiphertext(testDec[i].negate(), curve.getInfinity()), minerKey);

				CryptoData[] proverInputs = new CryptoData[3];
				proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(minerKey.getY()), new ECPointData((ECPoint) (dummyInputsRandomized[i].homomorphicAdd(dummyInputsDecrypted[i].negate(minerKey), minerKey).getCipher(minerKey)))});
				proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(minerPrivKey.getPrivKey()[0])});
				proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(test.getEphemeral(minerKey))});
				CryptoData a = null;
				try {
					a = proofOfStuff.initialComm(proverInputs[0], proverInputs[1], proverInputs[2]);
					CryptoData[] aUnpacked = a.getCryptoDataArray();
					combinedA[i][0] = aUnpacked[0].getECPointData(curve);
					combinedA[i][1] = aUnpacked[1].getECPointData(curve);
				} catch (MultipleTrueProofException	| NoTrueProofException | ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}

				for(int k = 0; k < in.length; k++) {
					if(out[k] == null) continue;
					try {
						out[k].writeObject(a);
						out[k].flush();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				for(int k = 0; k < in.length; k++) {
					if(in[k] == null) continue;
					try {
						a = (CryptoData) in[k].readObject();
						CryptoData[] aUnpacked = a.getCryptoDataArray();
						combinedA[i][0] = combinedA[i][0].add(aUnpacked[0].getECPointData(curve));
						combinedA[i][1] = combinedA[i][1].add(aUnpacked[1].getECPointData(curve));
					} catch (IOException | ClassNotFoundException e) {
						e.printStackTrace();
					}
				}
				dummyTableDecryptTranscript[i][0] = new CryptoDataArray(combinedA[i]);
				BigInteger challenge = proofOfStuff.fiatShamirChallange(proverInputs[0], dummyTableDecryptTranscript[i][0], proverInputs[2]);
				try {
					CryptoData z = proofOfStuff.calcResponse(proverInputs[0], proverInputs[1], challenge, proverInputs[2]);
					combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().mod(curve.getOrder());
					for(int k = 0; k < in.length; k++) {
						if(out[k] == null) continue;
						try {
							out[k].writeObject(z);
							out[k].flush();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
					for(int k = 0; k < in.length; k++) {
						if(in[k] == null) continue;
						try {
							z = (CryptoData) in[k].readObject();
							combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().add(combinedZ[i]).mod(curve.getOrder());
						} catch (IOException | ClassNotFoundException e) {
							e.printStackTrace();
						}
					}
				} catch (NoTrueProofException | MultipleTrueProofException e) {
					e.printStackTrace();
				}
					
				dummyTableDecryptTranscript[i][1] = new CryptoDataArray(new BigInteger[] {combinedZ[i]});
				try {
					if(proofOfStuff.verifyFiatShamir(proverInputs[0], dummyTableDecryptTranscript[i][0], dummyTableDecryptTranscript[i][1], proverInputs[2])) {
						
					} else {
						System.out.println("The dream is deaed :-( 0");
					}
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		AdditiveCiphertext dummyTableOutput = null;
		AdditiveCiphertext dummyFlagOutput = null;
		if(dummyInputsDecrypted[0].getCipher(minerKey).equals(curve.getInfinity())) {
			if(dummyInputsDecrypted[1].getCipher(minerKey).equals(curve.getInfinity())) {
				System.out.println("An extremely improbable error has occurred.");
				return false;
			} else {
				dummyTableOutput = intermediateDummyTables[in.length-1][0].output2;
				dummyFlagOutput = intermediateDummyTables[in.length-1][0].compare;
			}
		}else if(dummyInputsDecrypted[1].getCipher(minerKey).equals(curve.getInfinity())) {
			dummyTableOutput = intermediateDummyTables[in.length-1][1].output2;
			dummyFlagOutput = intermediateDummyTables[in.length-1][1].compare;
		} else {
			System.out.println("Something bad happened in dummy mix and match");
			return false;
		}
			// PASSWORD TIME  *************************************************************************************************************************************************************************
		
		ElectionTableRowInner[] passwordTable = new ElectionTableRowInner[2];
		passwordTable[0] = new ElectionTableRowInner(minerKey.getEmptyCiphertext().homomorphicAdd(dummyTableOutput.negate(minerKey), minerKey), voterVotes, dummyFlagOutput);
		passwordTable[1] = new ElectionTableRowInner(tableOmega.homomorphicAdd(passwordDifferenceCipher.negate(minerKey), minerKey), zeroVote, minerKey.encrypt(BigInteger.ONE, BigInteger.ZERO));
		//Shuffle Table
		
		{
			ZKPProtocol ballotTableProof;
			ZKPProtocol[] proofArray = new ZKPProtocol[2];
			ZKPProtocol[] midProof = new ZKPProtocol[3];
			ZKPProtocol[] midProof2 = new ZKPProtocol[2];
			midProof2[0] = midProof2[1] = minerKey.getZKPforRerandomization();
			midProof[0] = midProof[2] = new ZeroKnowledgeAndProver(midProof2);
			ZKPProtocol[] innerProof = new ZKPProtocol[election.getNumRace()];
			for(int i = 0; i < innerProof.length; i++) {
				ZKPProtocol[] innerInnerProof = new ZKPProtocol[2];
				innerInnerProof[0] = innerInnerProof[1] = zeroVote[i].getRandomizationProof(election.getRace(i).getPubKey());
				innerProof[i] = new ZeroKnowledgeAndProver(innerInnerProof);
			}
			midProof[1] = new ZeroKnowledgeAndProver(innerProof);
			proofArray[0] = proofArray[1] = new ZeroKnowledgeAndProver(midProof);
			ballotTableProof = new ZeroKnowledgeOrProver(proofArray, minerKey.getOrder());


			intermediatePasswordTables = new ElectionTableRowInner[in.length][];
			passwordProofTranscripts = new CryptoData[in.length][];
			int[] order = MinerThread.chooseOrder(in, out, minerKey, rand);
			for(int i = 0; i < in.length; i++) {
				ElectionTableRowInner[] orig;
				if(i == 0) orig = passwordTable;
				else orig = intermediatePasswordTables[i-1];
				if(in[order[i]] == null) { //my turn
					//decide whether to shuffle
					CryptoData[] proverInputs = new CryptoData[3];
					boolean swap = rand.nextBoolean();

					intermediatePasswordTables[i] = new ElectionTableRowInner[2];
					BigInteger compareRerandmize0 = minerKey.generateEphemeral(rand);
					BigInteger compareRerandmize1 = minerKey.generateEphemeral(rand);
					BigInteger[][][] raceRerandomizer = new BigInteger[2][election.getNumRace()][];
					BigInteger[] dummyFlagRerandomizer = new BigInteger[] {minerKey.generateEphemeral(rand), minerKey.generateEphemeral(rand)};
					for(int j = 0; j < election.getNumRace(); j++) {
						Race race = election.getRace(j);
						raceRerandomizer[0][j] = race.generateRerandimizationValues(rand);
						raceRerandomizer[1][j] = race.generateRerandimizationValues(rand);
					}
					if(swap) {
						intermediatePasswordTables[i][0] = orig[1].rerandomize(compareRerandmize0, raceRerandomizer[0], dummyFlagRerandomizer[0], election);
						intermediatePasswordTables[i][1] = orig[0].rerandomize(compareRerandmize1, raceRerandomizer[1], dummyFlagRerandomizer[1], election);
					} else {
						intermediatePasswordTables[i][0] = orig[0].rerandomize(compareRerandmize0, raceRerandomizer[0], dummyFlagRerandomizer[0], election);
						intermediatePasswordTables[i][1] = orig[1].rerandomize(compareRerandmize1, raceRerandomizer[1], dummyFlagRerandomizer[1], election);
					}
					for(int j = 0; j < in.length; j++) {
						if(out[j] != null) {
							try {
								out[j].writeObject(intermediatePasswordTables[i]);
								out[j].flush();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
					}
					CryptoData[] fullProofData = getSmallTableProverData(rand, election, minerKey, i, orig, swap,
							compareRerandmize0, compareRerandmize1, raceRerandomizer, intermediatePasswordTables, dummyFlagRerandomizer);

					try {
						passwordProofTranscripts[i] = ballotTableProof.proveFiatShamir(fullProofData[0], fullProofData[1], fullProofData[2]);
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
							| ArraySizesDoNotMatchException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					for(int j = 0; j < in.length; j++) {
						if(out[j] != null) {
							try {
								out[j].writeObject(passwordProofTranscripts[i]);
								out[j].flush();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						}
					}
				} else {
					//Other turn
					//decide whether to shuffle
					try {
						intermediatePasswordTables[i] = (ElectionTableRowInner[]) in[order[i]].readObject();
					} catch (ClassNotFoundException | IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

					CryptoData[] fullProofData = getSmallTableVerifierData(election, minerKey, i, orig, intermediatePasswordTables);
					try {
						passwordProofTranscripts[i] = (CryptoData[]) in[order[i]].readObject();
						if(!ballotTableProof.verifyFiatShamir(fullProofData[0], passwordProofTranscripts[i][0], passwordProofTranscripts[i][1], fullProofData[1])) {
							System.out.println("Failed Password Ballot Proof");
						}
					} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

				}

			}
		}
		
		
		passwordTableRandomizeTranscript = new CryptoData[2][2];
		ZKPProtocol proofOfStuff = new ECEqualDiscreteLogsProver();
		ECPoint[][] combinedA = new ECPoint[2][2];
		BigInteger[] combinedZ = new BigInteger[2];
		
		//first, randomize.  Then prove.
		BigInteger[] toScalarMultiply = new BigInteger[] {minerKey.generateEphemeral(rand), minerKey.generateEphemeral(rand)};
		passwordInputsRandomized = new AdditiveElgamalCiphertext[2];
		for(int i = 0; i < 2; i++) {
			passwordInputsRandomized[i] = (AdditiveElgamalCiphertext) intermediatePasswordTables[in.length-1][i].compare.scalarMultiply(toScalarMultiply[i], minerKey);

		}
		for(int k = 0; k < in.length; k++) {
			if(out[k] == null) continue;
			try {
				out[k].writeObject(passwordInputsRandomized);
				out[k].flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		for(int k = 0; k < in.length; k++) {
			if(in[k] == null) continue;
			try {
				AdditiveCiphertext[] other = (AdditiveCiphertext[]) in[k].readObject();
				for(int i = 0; i < 2; i++) {
					passwordInputsRandomized[i] = (AdditiveElgamalCiphertext) passwordInputsRandomized[i].homomorphicAdd(other[i], minerKey);
				}
			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		for(int i = 0; i < 2; i++) {

			AdditiveElgamalCiphertext test = (AdditiveElgamalCiphertext) intermediatePasswordTables[in.length - 1][i].compare;

			CryptoData[] proverInputs = new CryptoData[3];
			proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData((ECPoint) passwordInputsRandomized[i].getCipher(minerKey)), new ECPointData(passwordInputsRandomized[i].getEphemeral(minerKey))});
			proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(toScalarMultiply[i])});
			proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, (ECPoint) test.getCipher(minerKey)), new ECPointData(test.getEphemeral(minerKey))});
			CryptoData a = null;
			try {
				a = proofOfStuff.initialComm(proverInputs[0], proverInputs[1], proverInputs[2]);
				CryptoData[] aUnpacked = a.getCryptoDataArray();
				combinedA[i][0] = aUnpacked[0].getECPointData(curve);
				combinedA[i][1] = aUnpacked[1].getECPointData(curve);
			} catch (MultipleTrueProofException	| NoTrueProofException | ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			for(int k = 0; k < in.length; k++) {
				if(out[k] == null) continue;
				try {
					out[k].writeObject(a);
					out[k].flush();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			for(int k = 0; k < in.length; k++) {
				if(in[k] == null) continue;
				try {
					a = (CryptoData) in[k].readObject();
					CryptoData[] aUnpacked = a.getCryptoDataArray();
					combinedA[i][0] = combinedA[i][0].add(aUnpacked[0].getECPointData(curve));
					combinedA[i][1] = combinedA[i][1].add(aUnpacked[1].getECPointData(curve));
				} catch (IOException | ClassNotFoundException e) {
					e.printStackTrace();
				}
			}
			passwordTableRandomizeTranscript[i][0] = new CryptoDataArray(combinedA[i]);
			BigInteger challenge = proofOfStuff.fiatShamirChallange(proverInputs[0], passwordTableRandomizeTranscript[i][0], proverInputs[2]);
			try {
				CryptoData z = proofOfStuff.calcResponse(proverInputs[0], proverInputs[1], challenge, proverInputs[2]);
				combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().mod(curve.getOrder());
				for(int k = 0; k < in.length; k++) {
					if(out[k] == null) continue;
					try {
						out[k].writeObject(z);
						out[k].flush();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				for(int k = 0; k < in.length; k++) {
					if(in[k] == null) continue;
					try {
						z = (CryptoData) in[k].readObject();
						combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().add(combinedZ[i]).mod(curve.getOrder());
					} catch (IOException | ClassNotFoundException e) {
						e.printStackTrace();
					}
				}
			} catch (NoTrueProofException | MultipleTrueProofException e) {
				e.printStackTrace();
			}
				
			passwordTableRandomizeTranscript[i][1] = new CryptoDataArray(new BigInteger[] {combinedZ[i]});
			
			try {
				if(proofOfStuff.verifyFiatShamir(proverInputs[0], passwordTableRandomizeTranscript[i][0], passwordTableRandomizeTranscript[i][1], proverInputs[2])) {
					
				} else {
					System.out.println("The dream is deaed :-(");
				}
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
		
		

		passwordTableDecryptTranscript = new CryptoData[2][2];
		combinedA = new ECPoint[2][2];
		combinedZ = new BigInteger[2];
		
		//first, decrypt.  Then prove.
		toScalarMultiply = new BigInteger[] {minerKey.generateEphemeral(rand), minerKey.generateEphemeral(rand)};
		ECPoint[] testDec = new ECPoint[2];
		for(int i = 0; i < 2; i++) {
			testDec[i] = passwordInputsRandomized[i].getEphemeral(minerKey).multiply(minerPrivKey.getPrivKey()[0]);

		}
		for(int k = 0; k < in.length; k++) {
			if(out[k] == null) continue;
			try {
				out[k].writeObject(testDec[0].getEncoded(true));
				out[k].writeObject(testDec[1].getEncoded(true));
				out[k].flush();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		ECPoint[] other = new ECPoint[2];
		for(int k = 0; k < in.length; k++) {
			if(in[k] == null) continue;
			try {
				other[0] = curve.decodePoint((byte[]) in[k].readObject());
				other[1] = curve.decodePoint((byte[]) in[k].readObject());
				for(int i = 0; i < 2; i++) {
					testDec[i] = testDec[i].add(other[i]);
				}
			} catch (IOException | ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		passwordInputsDecrypted = new AdditiveElgamalCiphertext[2];
		for(int i = 0; i < 2; i++) {
			AdditiveElgamalCiphertext test = passwordInputsRandomized[i];
			passwordInputsDecrypted[i] = (AdditiveElgamalCiphertext) test.homomorphicAdd(new AdditiveElgamalCiphertext(testDec[i].negate(), curve.getInfinity()), minerKey);

			CryptoData[] proverInputs = new CryptoData[3];
			proverInputs[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(minerKey.getY()), new ECPointData((ECPoint) (passwordInputsRandomized[i].homomorphicAdd(passwordInputsDecrypted[i].negate(minerKey), minerKey).getCipher(minerKey)))});
			proverInputs[1] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(minerPrivKey.getPrivKey()[0])});
			proverInputs[2] = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, g), new ECPointData(test.getEphemeral(minerKey))});
			CryptoData a = null;
			try {
				a = proofOfStuff.initialComm(proverInputs[0], proverInputs[1], proverInputs[2]);
				CryptoData[] aUnpacked = a.getCryptoDataArray();
				combinedA[i][0] = aUnpacked[0].getECPointData(curve);
				combinedA[i][1] = aUnpacked[1].getECPointData(curve);
			} catch (MultipleTrueProofException	| NoTrueProofException | ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			for(int k = 0; k < in.length; k++) {
				if(out[k] == null) continue;
				try {
					out[k].writeObject(a);
					out[k].flush();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			for(int k = 0; k < in.length; k++) {
				if(in[k] == null) continue;
				try {
					a = (CryptoData) in[k].readObject();
					CryptoData[] aUnpacked = a.getCryptoDataArray();
					combinedA[i][0] = combinedA[i][0].add(aUnpacked[0].getECPointData(curve));
					combinedA[i][1] = combinedA[i][1].add(aUnpacked[1].getECPointData(curve));
				} catch (IOException | ClassNotFoundException e) {
					e.printStackTrace();
				}
			}
			passwordTableDecryptTranscript[i][0] = new CryptoDataArray(combinedA[i]);
			BigInteger challenge = proofOfStuff.fiatShamirChallange(proverInputs[0], passwordTableDecryptTranscript[i][0], proverInputs[2]);
			try {
				CryptoData z = proofOfStuff.calcResponse(proverInputs[0], proverInputs[1], challenge, proverInputs[2]);
				combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().mod(curve.getOrder());
				for(int k = 0; k < in.length; k++) {
					if(out[k] == null) continue;
					try {
						out[k].writeObject(z);
						out[k].flush();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				for(int k = 0; k < in.length; k++) {
					if(in[k] == null) continue;
					try {
						z = (CryptoData) in[k].readObject();
						combinedZ[i] = z.getCryptoDataArray()[0].getBigInt().add(combinedZ[i]).mod(curve.getOrder());
					} catch (IOException | ClassNotFoundException e) {
						e.printStackTrace();
					}
				}
			} catch (NoTrueProofException | MultipleTrueProofException e) {
				e.printStackTrace();
			}
				
			passwordTableDecryptTranscript[i][1] = new CryptoDataArray(new BigInteger[] {combinedZ[i]});
			
			
			try {
				if(proofOfStuff.verifyFiatShamir(proverInputs[0], passwordTableDecryptTranscript[i][0], passwordTableDecryptTranscript[i][1], proverInputs[2])) {
					
				} else {
					System.out.println("The dream is deaed :-( 2");
				}
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		if(passwordInputsDecrypted[0].getCipher(minerKey).equals(curve.getInfinity())) {
			if(passwordInputsDecrypted[1].getCipher(minerKey).equals(curve.getInfinity())) {
				System.out.println("Bad Password Table Error 1");
				return false;
			}
			countedVotes = intermediatePasswordTables[in.length-1][0].output1;
			dummyFlag = intermediatePasswordTables[in.length-1][0].output2;
		} else if(passwordInputsDecrypted[1].getCipher(minerKey).equals(curve.getInfinity())) {
			countedVotes = intermediatePasswordTables[in.length-1][1].output1;
			dummyFlag = intermediatePasswordTables[in.length-1][1].output2;
		} else {
			System.out.println("Bad Password Table Error 2");
			return false;
		}
		{
			ByteArrayOutputStream out1 = new ByteArrayOutputStream();
			try {
				ObjectOutputStream out2 = new ObjectOutputStream(out1);
				out2.writeObject(this);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}	
//		private CryptoData[][] dummyTableRandomizeTranscript;
//		private CryptoData[][] dummyTableDecryptTranscript;
//		private CryptoData[][] passwordTableRandomizeTranscript;
//		private ElectionTableRowInner[][] intermediatePasswordTables;
//		private CryptoData[][] passwordProofTranscripts;
//		private CryptoData[][] passwordTableDecryptTranscript;	
//		private ElectionTableRowInner[][] intermediateDummyTables;
//		private CryptoData[][] dummyProofTranscripts;
		{
			ByteArrayOutputStream out1 = new ByteArrayOutputStream();
			try {
				ObjectOutputStream out2 = new ObjectOutputStream(out1);
				out2.writeObject(dummyTableRandomizeTranscript);
				out2.writeObject(dummyTableDecryptTranscript);
				out2.writeObject(passwordTableRandomizeTranscript);
				out2.writeObject(intermediatePasswordTables);
				out2.writeObject(passwordProofTranscripts);
				out2.writeObject(passwordTableDecryptTranscript);
				out2.writeObject(intermediateDummyTables);
				out2.writeObject(dummyProofTranscripts);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		{
			ByteArrayOutputStream out1 = new ByteArrayOutputStream();
			try {
				ObjectOutputStream out2 = new ObjectOutputStream(out1);
				out2.writeObject(countedVotes);
				out2.writeObject(tableOmega);
				out2.writeObject(dummyInputsRandomized);
				out2.writeObject(dummyInputsDecrypted);
				out2.writeObject(passwordInputsRandomized);
				out2.writeObject(passwordInputsDecrypted);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return true;
	}

	@Override
	public CryptoData[] getSmallTableVerifierData(Election election, AdditiveElgamalPubKey minerKey, int i,
			ElectionTableRowInner[] orig, ElectionTableRowInner[][] originalTables) {
		CryptoData[] fullProofData = new CryptoData[2];
		CryptoData[] fullProofPub = new CryptoData[2];
		CryptoData[] fullProofEnv = new CryptoData[2];
		
		boolean hasOutput1 = (orig[0].output1 != null);
		boolean hasOutput2 = (orig[0].output2 != null);
		{//Build non-swap half of data
			CryptoData[] midPub;
			CryptoData[] midEnv;
			if(!hasOutput2 || !hasOutput1) {
				midPub = new CryptoData[2];
				midEnv = new CryptoData[2];
			} else {
				midPub = new CryptoData[3];
				midEnv = new CryptoData[3];
			}
			int count = 1;
			if(hasOutput1) {
				CryptoData[][] inner = new CryptoData[2][];
				CryptoData[][] innerPub = new CryptoData[election.getNumRace()][2];
				CryptoData[][] innerEnv = new CryptoData[election.getNumRace()][2];
				for(int j = 0; j < election.getNumRace(); j++) {
					inner[0] = originalTables[i][0].output1[j].getVerificationDataRandomizationProof(orig[0].output1[j], election.getRace(j).getPubKey());
					inner[1] = originalTables[i][1].output1[j].getVerificationDataRandomizationProof(orig[1].output1[j], election.getRace(j).getPubKey());
					innerPub[j][0] = inner[0][0];
					innerEnv[j][0] = inner[0][1];
					innerPub[j][1] = inner[1][0];
					innerEnv[j][1] = inner[1][1];
				}
				CryptoData[] inner2Pub = new CryptoData[election.getNumRace()];
				CryptoData[] inner2Env = new CryptoData[election.getNumRace()];
				for(int j = 0; j < inner2Pub.length; j++) {
					inner2Pub[j] = new CryptoDataArray(innerPub[j]);
					inner2Env[j] = new CryptoDataArray(innerEnv[j]);
				}
	
				midPub[count] = new CryptoDataArray(inner2Pub);
				midEnv[count] = new CryptoDataArray(inner2Env);
				count++;
			}
			CryptoData[][] mid2 = new CryptoData[2][]; 
			mid2[0] = originalTables[i][0].compare.getRerandomizationVerifierData(orig[0].compare, minerKey);
			mid2[1] = originalTables[i][1].compare.getRerandomizationVerifierData(orig[1].compare, minerKey);


			CryptoData[] mid2Pub = new CryptoData[2];
			mid2Pub[0] = mid2[0][0];
			mid2Pub[1] = mid2[1][0];
			CryptoData[] mid2Env = new CryptoData[2]; 
			mid2Env[0] = mid2[0][1];
			mid2Env[1] = mid2[1][1];

			midPub[0] = new CryptoDataArray(mid2Pub);
			midEnv[0] = new CryptoDataArray(mid2Env);

			CryptoData[][] mid3 = new CryptoData[2][]; 
			if(hasOutput2) {
				mid3[0] = originalTables[i][0].output2.getRerandomizationVerifierData(orig[0].output2, minerKey);
				mid3[1] = originalTables[i][1].output2.getRerandomizationVerifierData(orig[1].output2, minerKey);
				
				CryptoData[] mid3Pub = new CryptoData[2];
				mid3Pub[0] = mid3[0][0];
				mid3Pub[1] = mid3[1][0];
				CryptoData[] mid3Env = new CryptoData[2]; 
				mid3Env[0] = mid3[0][1];
				mid3Env[1] = mid3[1][1];
	
				midPub[count] = new CryptoDataArray(mid3Pub);
				midEnv[count] = new CryptoDataArray(mid3Env);
			}
			fullProofPub[0] = new CryptoDataArray(midPub);
			fullProofEnv[0] = new CryptoDataArray(midEnv);
		}
		{//Build swap half of data

			CryptoData[] midPub;
			CryptoData[] midEnv;
			if(!hasOutput1 || !hasOutput2) {
				midPub = new CryptoData[2];
				midEnv = new CryptoData[2];
			} else {
				midPub = new CryptoData[3];
				midEnv = new CryptoData[3];
			}
			int count = 1;
			if(hasOutput1) {
				CryptoData[][] innerPub = new CryptoData[election.getNumRace()][2];
				CryptoData[][] innerEnv = new CryptoData[election.getNumRace()][2];
				CryptoData[][] inner = new CryptoData[2][];
				for(int j = 0; j < election.getNumRace(); j++) {
					inner[0] = originalTables[i][0].output1[j].getVerificationDataRandomizationProof(orig[1].output1[j], election.getRace(j).getPubKey());
					inner[1] = originalTables[i][1].output1[j].getVerificationDataRandomizationProof(orig[0].output1[j], election.getRace(j).getPubKey());
	
					innerPub[j][0] = inner[0][0];
					innerEnv[j][0] = inner[0][1];
					innerPub[j][1] = inner[1][0];
					innerEnv[j][1] = inner[1][1];
				}
				
				CryptoData[] inner2Pub = new CryptoData[election.getNumRace()];
				CryptoData[] inner2Env = new CryptoData[election.getNumRace()];
				for(int j = 0; j < inner2Pub.length; j++) {
					inner2Pub[j] = new CryptoDataArray(innerPub[j]);
					inner2Env[j] = new CryptoDataArray(innerEnv[j]);
				}
	
				midPub[count] = new CryptoDataArray(inner2Pub);
				midEnv[count] = new CryptoDataArray(inner2Env);
				count++;
			}
			CryptoData[][] mid2 = new CryptoData[2][]; 
			mid2[0] = originalTables[i][0].compare.getRerandomizationVerifierData(orig[1].compare, minerKey);
			mid2[1] = originalTables[i][1].compare.getRerandomizationVerifierData(orig[0].compare, minerKey);


			CryptoData[] mid2Pub = new CryptoData[2];
			mid2Pub[0] = mid2[0][0];
			mid2Pub[1] = mid2[1][0];
			CryptoData[] mid2Env = new CryptoData[2]; 
			mid2Env[0] = mid2[0][1];
			mid2Env[1] = mid2[1][1];

			midPub[0] = new CryptoDataArray(mid2Pub);
			midEnv[0] = new CryptoDataArray(mid2Env);
			
			if(hasOutput2) {
				CryptoData[][] mid3 = new CryptoData[2][]; 
				mid3[0] = originalTables[i][0].output2.getRerandomizationVerifierData(orig[1].output2, minerKey);
				mid3[1] = originalTables[i][1].output2.getRerandomizationVerifierData(orig[0].output2, minerKey);
				
				CryptoData[] mid3Pub = new CryptoData[2];
				mid3Pub[0] = mid3[0][0];
				mid3Pub[1] = mid3[1][0];
				CryptoData[] mid3Env = new CryptoData[2]; 
				mid3Env[0] = mid3[0][1];
				mid3Env[1] = mid3[1][1];
	
				midPub[count] = new CryptoDataArray(mid3Pub);
				midEnv[count] = new CryptoDataArray(mid3Env);
			}

			fullProofPub[1] = new CryptoDataArray(midPub);
			fullProofEnv[1] = new CryptoDataArray(midEnv);
		}

		fullProofData[0] = new CryptoDataArray(fullProofPub);
		fullProofData[1] = new CryptoDataArray(fullProofEnv);
		return fullProofData;
	}

	@Override
	public CryptoData[] getSmallTableProverData(SecureRandom rand, Election election, AdditiveElgamalPubKey minerKey,
			int i, ElectionTableRowInner[] orig, boolean swap, BigInteger compareRerandmize0,
			BigInteger compareRerandmize1, BigInteger[][][] raceRerandomizer, ElectionTableRowInner[][] sourceTable,BigInteger[] outputCipherRerandmize) {
		CryptoData[] fullProofData = new CryptoData[3];
		CryptoData[] fullProofPub = new CryptoData[2];
		CryptoData[] fullProofSec = new CryptoData[3];
		CryptoData[] fullProofEnv = new CryptoData[2];
		

		boolean hasOutput2 = (orig[0].output2 != null);
		
		{//Build non-swap half of data
			CryptoData[] midSec;
			CryptoData[] midPub;
			CryptoData[] midEnv;
			if(orig[0].output2 == null || orig[0].output1 == null) {
				midPub = new CryptoData[2];
				midSec = new CryptoData[2];
				midEnv = new CryptoData[2];
			} else {
				midPub = new CryptoData[3];
				midSec = new CryptoData[3];
				midEnv = new CryptoData[3];
			}
			int count = 1;
			if(orig[0].output1 != null) {
				CryptoData[][] innerPub = new CryptoData[election.getNumRace()][2];
				CryptoData[][] innerSec = new CryptoData[election.getNumRace()][2];
				CryptoData[][] innerEnv = new CryptoData[election.getNumRace()][2];
				CryptoData[][] inner = new CryptoData[2][];
				if(swap) {
					for(int j = 0; j < election.getNumRace(); j++) {
						inner[0] = sourceTable[i][0].output1[j].getProverDataRandomizationProof(orig[0].output1[j], null, election.getRace(j).getPubKey(), rand);
						inner[1] = sourceTable[i][1].output1[j].getProverDataRandomizationProof(orig[1].output1[j], null, election.getRace(j).getPubKey(), rand);
						innerPub[j][0] = inner[0][0];
						innerSec[j][0] = inner[0][1];
						innerEnv[j][0] = inner[0][2];
						innerPub[j][1] = inner[1][0];
						innerSec[j][1] = inner[1][1];
						innerEnv[j][1] = inner[1][2];
					}
				} else {
					for(int j = 0; j < election.getNumRace(); j++) {
						inner[0] = sourceTable[i][0].output1[j].getProverDataRandomizationProof(orig[0].output1[j], raceRerandomizer[0][j], election.getRace(j).getPubKey(), rand);
						inner[1] = sourceTable[i][1].output1[j].getProverDataRandomizationProof(orig[1].output1[j], raceRerandomizer[1][j], election.getRace(j).getPubKey(), rand);
						innerPub[j][0] = inner[0][0];
						innerSec[j][0] = inner[0][1];
						innerEnv[j][0] = inner[0][2];
						innerPub[j][1] = inner[1][0];
						innerSec[j][1] = inner[1][1];
						innerEnv[j][1] = inner[1][2];
					}
				}

				CryptoData[] inner2Pub = new CryptoData[election.getNumRace()];
				CryptoData[] inner2Sec = new CryptoData[election.getNumRace()];
				CryptoData[] inner2Env = new CryptoData[election.getNumRace()];
				for(int j = 0; j < inner2Pub.length; j++) {
					inner2Pub[j] = new CryptoDataArray(innerPub[j]);
					inner2Sec[j] = new CryptoDataArray(innerSec[j]);
					inner2Env[j] = new CryptoDataArray(innerEnv[j]);
				}
	
				midPub[count] = new CryptoDataArray(inner2Pub);
				midSec[count] = new CryptoDataArray(inner2Sec);
				midEnv[count] = new CryptoDataArray(inner2Env);
				count++;
			}
			CryptoData[][] mid2 = new CryptoData[2][]; 
			if(swap) {
				mid2[0] = sourceTable[i][0].compare.getRerandomizationProverData(orig[0].compare, null, rand, minerKey);
				mid2[1] = sourceTable[i][1].compare.getRerandomizationProverData(orig[1].compare, null, rand, minerKey);
			} else {
				mid2[0] = sourceTable[i][0].compare.getRerandomizationProverData(orig[0].compare, compareRerandmize0, rand, minerKey);
				mid2[1] = sourceTable[i][1].compare.getRerandomizationProverData(orig[1].compare, compareRerandmize1, rand, minerKey);
			}

			CryptoData[] mid2Pub = new CryptoData[2];
			mid2Pub[0] = mid2[0][0];
			mid2Pub[1] = mid2[1][0];
			CryptoData[] mid2Sec = new CryptoData[2];
			mid2Sec[0] = mid2[0][1];
			mid2Sec[1] = mid2[1][1];
			CryptoData[] mid2Env = new CryptoData[2]; 
			mid2Env[0] = mid2[0][2];
			mid2Env[1] = mid2[1][2];


			midPub[0] = new CryptoDataArray(mid2Pub);
			midSec[0] = new CryptoDataArray(mid2Sec);
			midEnv[0] = new CryptoDataArray(mid2Env);
			
			if(hasOutput2) {
			CryptoData[][] mid3 = new CryptoData[2][]; 
				if(swap) {
					mid3[0] = sourceTable[i][0].output2.getRerandomizationProverData(orig[0].output2, null, rand, minerKey);
					mid3[1] = sourceTable[i][1].output2.getRerandomizationProverData(orig[1].output2, null, rand, minerKey);
				} else {
					mid3[0] = sourceTable[i][0].output2.getRerandomizationProverData(orig[0].output2, outputCipherRerandmize[0], rand, minerKey);
					mid3[1] = sourceTable[i][1].output2.getRerandomizationProverData(orig[1].output2, outputCipherRerandmize[1], rand, minerKey);
				}
				
				CryptoData[] mid3Pub = new CryptoData[2];
				mid3Pub[0] = mid3[0][0];
				mid3Pub[1] = mid3[1][0];
				CryptoData[] mid3Sec = new CryptoData[2];
				mid3Sec[0] = mid3[0][1];
				mid3Sec[1] = mid3[1][1];
				CryptoData[] mid3Env = new CryptoData[2]; 
				mid3Env[0] = mid3[0][2];
				mid3Env[1] = mid3[1][2];

				midPub[count] = new CryptoDataArray(mid3Pub);
				midSec[count] = new CryptoDataArray(mid3Sec);
				midEnv[count] = new CryptoDataArray(mid3Env);
			}
			
			fullProofPub[0] = new CryptoDataArray(midPub);
			fullProofSec[0] = new CryptoDataArray(midSec);
			fullProofEnv[0] = new CryptoDataArray(midEnv);
		}
		{//Build swap half of data
			CryptoData[] midSec;
			CryptoData[] midPub;
			CryptoData[] midEnv;
			if(orig[0].output2 == null || orig[0].output1 == null) {
				midPub = new CryptoData[2];
				midSec = new CryptoData[2];
				midEnv = new CryptoData[2];
			} else {
				midPub = new CryptoData[3];
				midSec = new CryptoData[3];
				midEnv = new CryptoData[3];
			}
			int count = 1;
			if(orig[0].output1 != null) {
				CryptoData[][] innerPub = new CryptoData[election.getNumRace()][2];
				CryptoData[][] innerSec = new CryptoData[election.getNumRace()][2];
				CryptoData[][] innerEnv = new CryptoData[election.getNumRace()][2];
				CryptoData[][] inner = new CryptoData[2][];
				if(swap) {
					for(int j = 0; j < election.getNumRace(); j++) {
						inner[0] = sourceTable[i][0].output1[j].getProverDataRandomizationProof(orig[1].output1[j], raceRerandomizer[0][j], election.getRace(j).getPubKey(), rand);
						inner[1] = sourceTable[i][1].output1[j].getProverDataRandomizationProof(orig[0].output1[j], raceRerandomizer[1][j], election.getRace(j).getPubKey(), rand);
						innerPub[j][0] = inner[0][0];
						innerSec[j][0] = inner[0][1];
						innerEnv[j][0] = inner[0][2];
						innerPub[j][1] = inner[1][0];
						innerSec[j][1] = inner[1][1];
						innerEnv[j][1] = inner[1][2];
	
					}
				} else {
					for(int j = 0; j < election.getNumRace(); j++) {
						inner[0] = sourceTable[i][0].output1[j].getProverDataRandomizationProof(orig[1].output1[j], null, election.getRace(j).getPubKey(), rand);
						inner[1] = sourceTable[i][1].output1[j].getProverDataRandomizationProof(orig[0].output1[j], null, election.getRace(j).getPubKey(), rand);
	
						innerPub[j][0] = inner[0][0];
						innerSec[j][0] = inner[0][1];
						innerEnv[j][0] = inner[0][2];
						innerPub[j][1] = inner[1][0];
						innerSec[j][1] = inner[1][1];
						innerEnv[j][1] = inner[1][2];
					}
				}
				CryptoData[] inner2Pub = new CryptoData[election.getNumRace()];
				CryptoData[] inner2Sec = new CryptoData[election.getNumRace()];
				CryptoData[] inner2Env = new CryptoData[election.getNumRace()];
				for(int j = 0; j < inner2Pub.length; j++) {
					inner2Pub[j] = new CryptoDataArray(innerPub[j]);
					inner2Sec[j] = new CryptoDataArray(innerSec[j]);
					inner2Env[j] = new CryptoDataArray(innerEnv[j]);
				}
	
				midPub[count] = new CryptoDataArray(inner2Pub);
				midSec[count] = new CryptoDataArray(inner2Sec);
				midEnv[count] = new CryptoDataArray(inner2Env);
				count++;
			}
			CryptoData[][] mid2 = new CryptoData[2][]; 
			if(swap) {
				mid2[0] = sourceTable[i][0].compare.getRerandomizationProverData(orig[1].compare, compareRerandmize0, rand, minerKey);
				mid2[1] = sourceTable[i][1].compare.getRerandomizationProverData(orig[0].compare, compareRerandmize1, rand, minerKey);
			} else {
				mid2[0] = sourceTable[i][0].compare.getRerandomizationProverData(orig[1].compare, null, rand, minerKey);
				mid2[1] = sourceTable[i][1].compare.getRerandomizationProverData(orig[0].compare, null, rand, minerKey);
			}

			CryptoData[] mid2Pub = new CryptoData[2];
			mid2Pub[0] = mid2[0][0];
			mid2Pub[1] = mid2[1][0];
			CryptoData[] mid2Sec = new CryptoData[2];
			mid2Sec[0] = mid2[0][1];
			mid2Sec[1] = mid2[1][1];
			CryptoData[] mid2Env = new CryptoData[2]; 
			mid2Env[0] = mid2[0][2];
			mid2Env[1] = mid2[1][2];

			midPub[0] = new CryptoDataArray(mid2Pub);
			midSec[0] = new CryptoDataArray(mid2Sec);
			midEnv[0] = new CryptoDataArray(mid2Env);
			if(hasOutput2) {
				CryptoData[][] mid3 = new CryptoData[2][]; 
				if(swap) {
					mid3[0] = sourceTable[i][0].output2.getRerandomizationProverData(orig[1].output2, outputCipherRerandmize[0], rand, minerKey);
					mid3[1] = sourceTable[i][1].output2.getRerandomizationProverData(orig[0].output2, outputCipherRerandmize[1], rand, minerKey);
				} else {
					mid3[0] = sourceTable[i][0].output2.getRerandomizationProverData(orig[1].output2, null, rand, minerKey);
					mid3[1] = sourceTable[i][1].output2.getRerandomizationProverData(orig[0].output2, null, rand, minerKey);
				}
				
				CryptoData[] mid3Pub = new CryptoData[2];
				mid3Pub[0] = mid3[0][0];
				mid3Pub[1] = mid3[1][0];
				CryptoData[] mid3Sec = new CryptoData[2];
				mid3Sec[0] = mid3[0][1];
				mid3Sec[1] = mid3[1][1];
				CryptoData[] mid3Env = new CryptoData[2]; 
				mid3Env[0] = mid3[0][2];
				mid3Env[1] = mid3[1][2];
	
				midPub[count] = new CryptoDataArray(mid3Pub);
				midSec[count] = new CryptoDataArray(mid3Sec);
				midEnv[count] = new CryptoDataArray(mid3Env);
			}
			fullProofPub[1] = new CryptoDataArray(midPub);
			fullProofSec[1] = new CryptoDataArray(midSec);
			fullProofEnv[1] = new CryptoDataArray(midEnv);
		}
		CryptoData[] simulatedChallenges = new CryptoData[2];
		if(swap) {
			simulatedChallenges[0] = new BigIntData(minerKey.generateEphemeral(rand));
			simulatedChallenges[1] = new BigIntData(null);
		} else {
			simulatedChallenges[0] = new BigIntData(null);
			simulatedChallenges[1] = new BigIntData(minerKey.generateEphemeral(rand));
		}
		fullProofSec[2] = new CryptoDataArray(simulatedChallenges);

		fullProofData[0] = new CryptoDataArray(fullProofPub);
		fullProofData[1] = new CryptoDataArray(fullProofSec);
		fullProofData[2] = new CryptoDataArray(fullProofEnv);
		return fullProofData;
	}

	private AdditiveCiphertext[][] shuffleInternal(AdditiveCiphertext[][] table1, ObjectInputStream[] in,
			ObjectOutputStream[] out, AdditiveElgamalPubKey minerKey, SecureRandom rand) {
		int rows = table1.length;
		int cols = table1[0].length;
		//		System.out.println("Entering shuffleInternal " + Thread.currentThread().toString());
		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();
		ECPoint y = minerKey.getY();
		int[] order = MinerThread.chooseOrder(in, out, minerKey, rand);
		AdditiveCiphertext[][][] table2s = new AdditiveCiphertext[in.length][][];

		ZKPProtocol proof1 = getInternalShuffleProof(table1, minerKey);
		//		Thread[] verifiers = new Thread[in.length];
		//		ParallelVerifier[] verifierObs = new ParallelVerifier[in.length];
		table2s[order[order.length-1]] = table1;
		for(int i = 0; i < in.length; i++) {
			int index = order[i];
			int prev;
			if(i == 0) {
				prev = order[order.length-1];
			} else {
				prev = order[i-1];
			}
			if(in[index] == null) {
//				System.out.println("My turn:  " + index);
				int[] shuffle = new int[rows];
				for(int k = 0; k < rows; k++) {
					shuffle[k] = k;
				}
				table2s[index] = new AdditiveElgamalCiphertext[rows][cols];
				for(int k = 0; k < rows-1; k++) {
					int randIndex = rand.nextInt(rows-k) + k;
					int temp = shuffle[randIndex];
					shuffle[randIndex] = shuffle[k];
					shuffle[k] = temp;
				}
				BigInteger[][] ephemerals = new BigInteger[rows][cols];
				for(int k = 0; k < rows; k++) {
					for(int k2 = 0; k2 < cols; k2++) {
						ephemerals[k][k2] = minerKey.generateEphemeral(rand);
						table2s[index][k][k2] = table2s[prev][shuffle[k]][k2].rerandomize(ephemerals[k][k2], minerKey);
					}
				}
				//				System.out.println(java.util.Arrays.toString(shuffle));
				CryptoData[] proverData = getInternalShuffleProverData(table2s[index], table2s[prev], ephemerals, shuffle, minerKey, rand);
				CryptoData[] proofTranscript = null;
				try {
					proofTranscript = proof1.proveFiatShamir(proverData[0], proverData[1], proverData[2]);
					//					CryptoData[] verifierData = getInternalShuffleVerifierData(table2s[index], table2s[prev], minerKey);
					//					if(verifierData[0].equals(proverData[0])) System.out.println("equal 1");
					//					else {
					//						System.out.println("not equal 1");
					//						System.out.println("v = " + verifierData[0]);
					//						System.out.println("p = " + proverData[0]);
					//					}
					//					
					//					if(verifierData[1].equals(proverData[2])) System.out.println("equal 2");
					//					else System.out.println("not equal 2");
					//					System.out.println(proof1.verifyFiatShamir(proverData[0], proofTranscript[0], proofTranscript[1], proverData[2]));
					//					System.out.println(proof1.verifyFiatShamir(verifierData[0], proofTranscript[0], proofTranscript[1], verifierData[1]));
				} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
						| ArraySizesDoNotMatchException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				for(int k = 0; k < out.length; k++) {
					if(out[k] == null) continue;
					try {
						//						System.out.println(Thread.currentThread() + " writing to " + k);
						out[k].writeObject(table2s[index]);
						out[k].writeObject(proofTranscript);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
				for(int k = 0; k < out.length; k++) {

					if(out[k] == null) continue;
					try {
						out[k].flush();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			} else {
				try {
					//					System.out.println(Thread.currentThread().toString() + " is waiting for " + i + " from " + index);
					table2s[index] = (AdditiveCiphertext[][]) in[index].readObject();
					CryptoData[] transcript = (CryptoData[]) in[index].readObject();

					CryptoData[] verifierInputs = getInternalShuffleVerifierData(table2s[index], table2s[prev], minerKey);
					//					System.out.println(Thread.currentThread().toString() + " has received " + i);

					//					verifiers[index] = new Thread(verifierObs[index] = new ParallelVerifier(proof1, transcript, verifierInputs));
					//					verifiers[index].setPriority(1);
					//					verifiers[index].start();

					try {
						if(!proof1.verifyFiatShamir(verifierInputs[0], transcript[0], transcript[1], verifierInputs[1])) {
							return null;
						}
					} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					//					
				} catch (ClassNotFoundException | IOException e) {
					e.printStackTrace();
				}
			}
		}
		//		for(int i = 0; i < in.length; i++) {
		//			if(in[i] == null) continue;
		//			try {
		//				verifiers[i].join();
		//			} catch (InterruptedException e) {
		//				// TODO Auto-generated catch block
		//				e.printStackTrace();
		//			}
		//			System.out.println(verifierObs[i].isVerified());
		//		}
		return table2s[order[order.length-1]];
	}

	class ParallelVerifier implements Runnable {
		private ZKPProtocol p;
		private CryptoData[] transcript;
		private CryptoData[] verifierInputs;
		private boolean verified = false;

		public ParallelVerifier(ZKPProtocol p, CryptoData[] transcript, CryptoData[] verifierInputs) {
			this.p = p;
			this.transcript = transcript;
			this.verifierInputs = verifierInputs;
		}

		public boolean isVerified() {
			return verified;
		}

		@Override
		public void run() {
			// TODO Auto-generated method stub
			try {
				verified = p.verifyFiatShamir(verifierInputs[0], transcript[0], transcript[1], verifierInputs[1]);
			} catch (ClassNotFoundException | IOException | MultipleTrueProofException | NoTrueProofException
					| ArraySizesDoNotMatchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}	
	}

	private CryptoData[] getInternalShuffleProverData(AdditiveCiphertext[][] table, AdditiveCiphertext[][] tableOrig,
			BigInteger[][] ephemerals, int[] shuffle, AdditiveElgamalPubKey minerKey, SecureRandom rand) {

		int rows = table.length;
		int cols = table[0].length;

		CryptoData[] toReturn = new CryptoData[3];
		CryptoData[] outerPub = new CryptoData[rows];
		CryptoData[] outerSec = new CryptoData[rows];
		CryptoData[] outerEnv = new CryptoData[rows];


		for(int i = 0; i < rows; i++) {
			CryptoData[] simulatedChallenges = new CryptoData[rows];

			CryptoData[] midPub = new CryptoData[rows];
			CryptoData[] midSec = new CryptoData[rows+1];
			CryptoData[] midEnv = new CryptoData[rows];
			for(int j = 0; j < rows; j++) {
				CryptoData[] innerPub = new CryptoData[cols];
				CryptoData[] innerSec = new CryptoData[cols];
				CryptoData[] innerEnv = new CryptoData[cols];

				CryptoData[][] temp = new CryptoData[cols][];
				for(int k = 0; k < cols; k++) {
					if(shuffle[i] == j) {
						simulatedChallenges[j] = new BigIntData(null);
						temp[k] = table[i][k].getRerandomizationProverData(tableOrig[j][k], ephemerals[i][k], rand, minerKey);
					} else {
						simulatedChallenges[j] = new BigIntData(minerKey.generateEphemeral(rand));
						temp[k] = table[i][k].getRerandomizationProverData(tableOrig[j][k], null, rand, minerKey);
					}
					innerPub[k] = temp[k][0];
					innerSec[k] = temp[k][1];
					innerEnv[k] = temp[k][2];
				}
				midPub[j] = new CryptoDataArray(innerPub);
				midSec[j] = new CryptoDataArray(innerSec);
				midEnv[j] = new CryptoDataArray(innerEnv);
			}
			midSec[rows] = new CryptoDataArray(simulatedChallenges);
			outerPub[i] = new CryptoDataArray(midPub);
			outerSec[i] = new CryptoDataArray(midSec);
			outerEnv[i] = new CryptoDataArray(midEnv);
		}
		toReturn[0] = new CryptoDataArray(outerPub);
		toReturn[1] = new CryptoDataArray(outerSec);
		toReturn[2] = new CryptoDataArray(outerEnv);

		return toReturn;
	}

	private CryptoData[] getInternalShuffleVerifierData(AdditiveCiphertext[][] table, AdditiveCiphertext[][] tableOrig, AdditiveElgamalPubKey minerKey) {

		int rows = table.length;
		int cols = table[0].length;

		CryptoData[] toReturn = new CryptoData[2];
		CryptoData[] outerPub = new CryptoData[rows];
		CryptoData[] outerEnv = new CryptoData[rows];


		for(int i = 0; i < rows; i++) {

			CryptoData[] midPub = new CryptoData[rows];
			CryptoData[] midEnv = new CryptoData[rows];
			for(int j = 0; j < rows; j++) {
				CryptoData[] innerPub = new CryptoData[cols];
				CryptoData[] innerEnv = new CryptoData[cols];

				CryptoData[][] temp = new CryptoData[cols][];

				for(int k = 0; k < cols; k++) {
					temp[k] = table[i][k].getRerandomizationVerifierData(tableOrig[j][k], minerKey);
					innerPub[k] = temp[k][0];
					innerEnv[k] = temp[k][1];
				}
				midPub[j] = new CryptoDataArray(innerPub);
				midEnv[j] = new CryptoDataArray(innerEnv);
			}
			outerPub[i] = new CryptoDataArray(midPub);
			outerEnv[i] = new CryptoDataArray(midEnv);
		}
		toReturn[0] = new CryptoDataArray(outerPub);
		toReturn[1] = new CryptoDataArray(outerEnv);

		return toReturn;
	}

	private ZKPProtocol getInternalShuffleProof(AdditiveCiphertext[][] table, AdditiveElgamalPubKey minerKey) {
		int rows = table.length;
		int cols = table[0].length;
		ZKPProtocol innerProof = minerKey.getZKPforRerandomization();
		ZKPProtocol[] innerAnd = new ZKPProtocol[cols];
		for(int k = 0; k < cols; k++) {
			innerAnd[k] = innerProof;
		}
		ZKPProtocol andPortion = new ZeroKnowledgeAndProver(innerAnd);
		ZKPProtocol[] orPortion = new ZKPProtocol[rows];
		for(int i = 0; i < orPortion.length; i++) {
			orPortion[i] = andPortion;
		}
		ZKPProtocol or = new ZeroKnowledgeOrProver(orPortion, minerKey.getOrder());
		ZKPProtocol[] outerAnd = new ZKPProtocol[rows];
		for(int i = 0; i < outerAnd.length; i++) {
			outerAnd[i] = or;
		}
		return new ZeroKnowledgeAndProver(outerAnd);

	}

	public static AdditiveCiphertext[] randomBits(int numBits, AdditiveElgamalPubKey minerKey, SecureRandom rand, ObjectOutputStream[] out, ObjectInputStream[] in) {
		AdditiveElgamalCiphertext[] toReturn = new AdditiveElgamalCiphertext[numBits];
		for(int i = 0; i < toReturn.length; i++) {
			toReturn[i] = (AdditiveElgamalCiphertext) minerKey.encrypt(BigInteger.ZERO, BigInteger.ZERO);
		}
		ECPoint g = minerKey.getG();
		ECPoint h = minerKey.getY();
		ECCurve curve = g.getCurve();
		CryptoData env;
		ZKPProtocol proof;
		{
			CryptoData innerEnv = new CryptoDataArray(new CryptoData[] {new ECCurveData(curve, h), new ECPointData(g)});
			env = new CryptoDataArray(new CryptoData[] {innerEnv, innerEnv});
			ZKPProtocol innerProof = new ECSchnorrCombinations(new int[][][] {{{0,0}}, {{1,0}}});
			proof = new ZeroKnowledgeOrProver(new ZKPProtocol[] {innerProof, innerProof}, curve.getOrder());
		}
		int[] order = MinerThread.chooseOrder(in, out, minerKey, rand);
		try {
			for(int i = 0; i < in.length; i++) {
				if (in[order[i]] == null) {
					AdditiveElgamalCiphertext[] newToReturn = new AdditiveElgamalCiphertext[numBits];
					CryptoData[][] transcripts = new CryptoData[numBits][];
					for(int j = 0; j < numBits; j++) {
						BigInteger bit = new BigInteger(1, rand);
//						System.out.printf("fhdsaighfdjkhgj %d, %d, %s\n",order[i], j, bit);
//						System.out.flush();
						BigInteger ephemeral = minerKey.generateEphemeral(rand);
						AdditiveElgamalCiphertext addedPortion = toReturn[j].scalarMultiply(BigInteger.TWO.negate(), minerKey).scalarMultiply(bit, minerKey).homomorphicAdd(minerKey.encrypt(bit, ephemeral), minerKey);
						newToReturn[j] = toReturn[j].homomorphicAdd(addedPortion, minerKey);
						
						CryptoData[] pubInput = new CryptoData[2];
						AdditiveElgamalCiphertext addedPortionIfOne = toReturn[j].scalarMultiply(BigInteger.TWO.negate(), minerKey).scalarAdd(BigInteger.ONE, minerKey);
						AdditiveElgamalCiphertext remainder0 = newToReturn[j].homomorphicAdd(toReturn[j].negate(minerKey), minerKey);
						AdditiveElgamalCiphertext remainder1 = remainder0.homomorphicAdd(addedPortionIfOne.negate(minerKey), minerKey);

						pubInput[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(remainder0.getCipher(minerKey)), new ECPointData(remainder0.getEphemeral(minerKey))});
						pubInput[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(remainder1.getCipher(minerKey)), new ECPointData(remainder1.getEphemeral(minerKey))});

						CryptoData[] secInput = new CryptoData[3];
						if(bit.equals(BigInteger.ZERO)) {
							secInput[0] = new CryptoDataArray(new BigInteger[] {minerKey.generateEphemeral(rand), ephemeral});
							secInput[1] = new CryptoDataArray(new BigInteger[] {minerKey.generateEphemeral(rand)});
							secInput[2] = new CryptoDataArray(new CryptoData[] {new BigIntData(null), new BigIntData(minerKey.generateEphemeral(rand))});
						} else {
							secInput[0] = new CryptoDataArray(new BigInteger[] {minerKey.generateEphemeral(rand)});
							secInput[1] = new CryptoDataArray(new BigInteger[] {minerKey.generateEphemeral(rand), ephemeral});
							secInput[2] = new CryptoDataArray(new CryptoData[] {new BigIntData(minerKey.generateEphemeral(rand)), new BigIntData(null)});
						}
						try {
							transcripts[j] = proof.proveFiatShamir(new CryptoDataArray(pubInput), new CryptoDataArray(secInput), env);
						} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
						
						try {
							if(proof.verifyFiatShamir(new CryptoDataArray(pubInput), transcripts[j][0], transcripts[j][1], env)) {
								
							} else System.out.println("Fail 24361532");
						} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					
					for(int j = 0; j < in.length; j++) {
						if(out[order[j]] != null) {
							out[order[j]].writeObject(newToReturn);
							out[order[j]].writeObject(transcripts);
							out[order[j]].flush();
						}
					}
					toReturn = newToReturn;
				} else {
					AdditiveElgamalCiphertext[] newToReturn = (AdditiveElgamalCiphertext[]) in[order[i]].readObject();
					CryptoData[][] transcripts = (CryptoData[][]) in[order[i]].readObject();
					for(int j = 0; j < numBits; j++) {
						AdditiveElgamalCiphertext addedPortion = newToReturn[j].homomorphicAdd(toReturn[j].negate(minerKey), minerKey);//toReturn[j].scalarMultiply(BigInteger.TWO.negate(), minerKey).scalarMultiply(bit, minerKey).homomorphicAdd(minerKey.encrypt(bit, ephemeral), minerKey);
						newToReturn[j] = toReturn[j].homomorphicAdd(addedPortion, minerKey);
						
						CryptoData[] pubInput = new CryptoData[2];
						AdditiveElgamalCiphertext addedPortionIfOne = toReturn[j].scalarMultiply(BigInteger.TWO.negate(), minerKey).scalarAdd(BigInteger.ONE, minerKey);

						AdditiveElgamalCiphertext remainder0 = newToReturn[j].homomorphicAdd(toReturn[j].negate(minerKey), minerKey);
						AdditiveElgamalCiphertext remainder1 = remainder0.homomorphicAdd(addedPortionIfOne.negate(minerKey), minerKey);

						pubInput[0] = new CryptoDataArray(new CryptoData[] {new ECPointData(remainder0.getCipher(minerKey)), new ECPointData(remainder0.getEphemeral(minerKey))});
						pubInput[1] = new CryptoDataArray(new CryptoData[] {new ECPointData(remainder1.getCipher(minerKey)), new ECPointData(remainder1.getEphemeral(minerKey))});
						try {
							if(proof.verifyFiatShamir(new CryptoDataArray(pubInput), transcripts[j][0], transcripts[j][1], env)) {
								
							} else System.out.println("Fail ghfdkjshg");
						} catch (MultipleTrueProofException | NoTrueProofException | ArraySizesDoNotMatchException e) {
							// TODO Auto-generated catch block
							e.printStackTrace();
						}
					}
					toReturn = newToReturn;
				}
			}
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		return toReturn;
	}
}
