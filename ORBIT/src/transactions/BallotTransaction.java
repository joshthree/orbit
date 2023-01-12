package transactions;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import blah.AdditiveCiphertext;
import blah.AdditiveElgamalCiphertext;
import blah.AdditiveElgamalPubKey;
import blah.Additive_Priv_Key;
import blah.Additive_Pub_Key;
import election.Election;
import election.EncryptedVote;
import zero_knowledge_proofs.ECDummyBallot10bProver;
import zero_knowledge_proofs.ECDummyBallot10dProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsForAnyNumberProver;
import zero_knowledge_proofs.ECEqualDiscreteLogsProver;
import zero_knowledge_proofs.ZKPProtocol;
import zero_knowledge_proofs.ZKToolkit;
import zero_knowledge_proofs.ZeroKnowledgeAndProver;
import zero_knowledge_proofs.ZeroKnowledgeOrProver;
import zero_knowledge_proofs.CryptoData.BigIntData;
import zero_knowledge_proofs.CryptoData.CryptoData;
import zero_knowledge_proofs.CryptoData.CryptoDataArray;
import zero_knowledge_proofs.CryptoData.ECCurveData;
import zero_knowledge_proofs.CryptoData.ECPointData;

public class BallotTransaction implements Transaction {
	private SourceTransaction[] ringMembers;
	private EncryptedVote[] voterVotes;

	private Additive_Pub_Key voterKey;
	
	private EncryptedVote[] countedVotes;
	
	private AdditiveCiphertext blindedPasswordOrigDecrypted;
	private AdditiveCiphertext blindedPasswordGuessDecrypted;
	
	private AdditiveCiphertext password;
	private AdditiveCiphertext dummyFlag;
	private AdditiveCiphertext encryptedOldKey;
	private AdditiveCiphertext origDummy2;
	private AdditiveCiphertext origPassword2;
	private AdditiveCiphertext passwordGuessCipher;
	private AdditiveCiphertext origPassword2Blinded;
	private AdditiveCiphertext passwordGuessCipherBlinded;
	private ECPoint keyImage;
	
	private int position = -1;
	
	private BallotTransaction(SourceTransaction[] ringMembers, int source, Additive_Priv_Key signingKey, Additive_Priv_Key newKey, BigInteger password, Election election, EncryptedVote[] votes, BigInteger passwordRandomization, SecureRandom rand){
		voterVotes = votes;
		this.ringMembers = ringMembers;
		//Execute Dummy Ballot part 1
		//Step 1:
		voterKey = newKey.getPubKey();
		//Step 2:
		BigInteger sourceVoterPrivKey = signingKey.getPrivKey()[0];
		BigInteger oldKeyR = voterKey.generateEphemeral(rand);
		AdditiveElgamalPubKey minerKey = election.getMinerKey();
		Additive_Pub_Key fullPasswordKey = minerKey.combineKeys(voterKey);
		encryptedOldKey = fullPasswordKey.encrypt(sourceVoterPrivKey, oldKeyR);
		
		//Step 3:
		AdditiveCiphertext origDummy1 = ringMembers[source].getDummyFlag();
		
		BigInteger origDummyR1 = minerKey.generateEphemeral(rand);
		origDummy2 = ringMembers[source].getPasswordCiphertext().rerandomize(origDummyR1, minerKey);
		

		Additive_Pub_Key origPassPub = minerKey.combineKeys(ringMembers[source].getVoterPubKey());
		AdditiveCiphertext origPassword1 = ringMembers[source].getPasswordCiphertext();
		BigInteger origPasswordR1 = origPassPub.generateEphemeral(rand);
		origPassword2 = ringMembers[source].getPasswordCiphertext().rerandomize(origPasswordR1, origPassPub);
		
		//Step 4: in arguments
		
		//Step 5:
		
		
		BigInteger passwordR = fullPasswordKey.generateEphemeral(rand);
		passwordGuessCipher = fullPasswordKey.encrypt(password, passwordR);
		
		//Step 6:
		MessageDigest fastHashDigest = null;
		try {
			fastHashDigest = MessageDigest.getInstance("Keccak-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] keyImageHash = fastHashDigest.digest(ringMembers[source].getVoterPubKey().getPublicKey());
		ECCurve curve = minerKey.getCurve();
		ECPoint g = minerKey.getG();
		ECPoint h1 = curve.decodePoint(fullPasswordKey.getPublicKey());
		keyImage = g.multiply(new BigInteger(keyImageHash).mod(minerKey.getOrder())).multiply(sourceVoterPrivKey.add(password).mod(minerKey.getOrder()));
		//TODO Should be direct Hash to Point, but this will do for now
		
		//Step 7:
		BigInteger passwordRandomizationGamma = fullPasswordKey.generateEphemeral(rand);
		origPassword2Blinded = origPassword2.scalarMultiply(passwordRandomizationGamma, origPassPub);
		passwordGuessCipherBlinded = passwordGuessCipher.scalarMultiply(passwordRandomizationGamma, fullPasswordKey);
		
		//Step 8:
		blindedPasswordOrigDecrypted = signingKey.decrypt(origPassword2Blinded);
		
		//Step 9:
		blindedPasswordGuessDecrypted = newKey.decrypt(passwordGuessCipherBlinded);
		
		//Step 10:  Proofs
		ZKPProtocol fullProof = getVoterProof(ringMembers, minerKey);
		
		
		//Generate CryptoData for Proofs.
		CryptoData[] fullProofData = new CryptoData[3];//0 for public, 1 for secret, 2 for environment
		CryptoData[][] fullProofDataUnpacked = new CryptoData[3][5];//0 for public, 1 for secret, 2 for environment
		CryptoData[][] proofOfMatchingData = new CryptoData[3][];
		proofOfMatchingData[0] = new CryptoData[ringMembers.length];
		proofOfMatchingData[1] = new CryptoData[ringMembers.length+1];
		proofOfMatchingData[2] = new CryptoData[ringMembers.length];
		BigInteger[] simulatedChallenges = new BigInteger[ringMembers.length];
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
				Additive_Pub_Key origPassPubRing = minerKey.combineKeys(ringMembers[source].getVoterPubKey());
				CryptoData[] proofOfMatchingDataInner = new CryptoData[3];
				AdditiveElgamalCiphertext newCipher = (AdditiveElgamalCiphertext) encryptedOldKey.homomorphicAdd(new AdditiveElgamalCiphertext(signingPub, curve.getInfinity()).negate(origPassPubRing),origPassPubRing);
				innerFirstPub[0] = new ECPointData((ECPoint) newCipher.getCipher(origPassPubRing));
				innerFirstPub[1] = new ECPointData(newCipher.getEphemeral(origPassPubRing));
				CryptoData[] dummyInputs;
				CryptoData[] passwordInputs;
				AdditiveCiphertext sourceOrigDummy = ringMembers[i].getDummyFlag();
				innerFirstSec[0] = new BigIntData(minerKey.generateEphemeral(rand));
				if(i == source) {
					innerFirstSec[1] = new BigIntData(sourceVoterPrivKey);
					dummyInputs = origDummy2.getRerandomizationProverData(ringMembers[i].getDummyFlag(), origDummyR1, rand, minerKey);
					passwordInputs = origPassword2.getRerandomizationProverData(ringMembers[i].getPasswordCiphertext(), origPasswordR1, rand, origPassPubRing);
					simulatedChallenges[i] = minerKey.generateEphemeral(rand);
				} else {
					dummyInputs = origDummy2.getRerandomizationProverData(sourceOrigDummy, null, rand, minerKey);					
					passwordInputs = origPassword2.getRerandomizationProverData(ringMembers[i].getPasswordCiphertext(), null, rand, origPassPubRing);
					simulatedChallenges[i] = null;
				}
				
				
				proofOfMatchingDataInner[0] = new CryptoDataArray(innerFirstPub);
				proofOfMatchingDataInner[1] = new CryptoDataArray(innerFirstSec);
				proofOfMatchingDataInner[2] = new CryptoDataArray(innerFirstEnv);
				proofOfMatchingData[0][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[0],
						dummyInputs[0],
						passwordInputs[0]
				});

				proofOfMatchingData[1][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[1],
						dummyInputs[1],
						passwordInputs[1]
				});
				
				proofOfMatchingData[2][i] = new CryptoDataArray(new CryptoData[] {
						proofOfMatchingDataInner[2],
						dummyInputs[2],
						passwordInputs[2]
				});
			}
			
			
//			proofOfMatchingData[i][1] = encryptedOldKey.getRerandomization; 
		}
		proofOfMatchingData[1][proofOfMatchingData[1].length-1] = new CryptoDataArray(simulatedChallenges);
		fullProofDataUnpacked[0][0] = new CryptoDataArray(proofOfMatchingData[0]);
		fullProofDataUnpacked[1][0] = new CryptoDataArray(proofOfMatchingData[1]);
		fullProofDataUnpacked[2][0] = new CryptoDataArray(proofOfMatchingData[2]);
		
		ECPoint[] publicForKeyImageProof = new ECPoint[5];
		publicForKeyImageProof[0] = keyImage;
		publicForKeyImageProof[1] = (ECPoint) encryptedOldKey.getCipher(minerKey);
		publicForKeyImageProof[2] = ((AdditiveElgamalCiphertext) encryptedOldKey).getEphemeral(minerKey);
		publicForKeyImageProof[3] = (ECPoint) passwordGuessCipher.getCipher(minerKey);
		publicForKeyImageProof[4] = ((AdditiveElgamalCiphertext) passwordGuessCipher).getEphemeral(minerKey);
		
		BigInteger[] secretsForKeyImageProof = new BigInteger[8];
		for(int i = 0; i < 4; i++) {
			secretsForKeyImageProof[i] = minerKey.generateEphemeral(rand);
		}
		secretsForKeyImageProof[4] = sourceVoterPrivKey;
		secretsForKeyImageProof[5] = password;
		secretsForKeyImageProof[6] = oldKeyR;
		secretsForKeyImageProof[7] = passwordR;
		
		
		CryptoData[] envForKeyImageProof = new CryptoData[5];
		
		envForKeyImageProof[0] = new ECCurveData(curve, keyImage);
		envForKeyImageProof[1] = new ECPointData(g);
		envForKeyImageProof[2] = new ECPointData(curve.decodePoint(fullPasswordKey.getPublicKey()));
		envForKeyImageProof[3] = new ECPointData(g);
		envForKeyImageProof[4] = new ECPointData(curve.decodePoint(fullPasswordKey.getPublicKey()));
		
		fullProofDataUnpacked[0][1] = new CryptoDataArray(publicForKeyImageProof);
		fullProofDataUnpacked[1][1] = new CryptoDataArray(secretsForKeyImageProof);
		fullProofDataUnpacked[2][1] = new CryptoDataArray(envForKeyImageProof);
		
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
		
		fullProofDataUnpacked[0][2] = new CryptoDataArray(publicForPasswordBlinding);
		fullProofDataUnpacked[1][2] = new CryptoDataArray(secretsForPasswordBlinding);
		fullProofDataUnpacked[2][2] = new CryptoDataArray(envForPasswordBlinding);
		
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

		fullProofDataUnpacked[0][3] = new CryptoDataArray(publicForOrigDecrypt);
		fullProofDataUnpacked[1][3] = new CryptoDataArray(secretsForOrigDecrypt);
		fullProofDataUnpacked[2][3] = new CryptoDataArray(envForOrigDecrypt);

		//DONE WITH D, NOW DOING E
		
		ECPoint[] publicForGuessDecrypt = new ECPoint[2];
		
		AdditiveElgamalCiphertext diff2 = (AdditiveElgamalCiphertext) passwordGuessCipherBlinded.homomorphicAdd(blindedPasswordGuessDecrypted.negate(minerKey), minerKey);
		
		publicForGuessDecrypt[0] = (ECPoint) diff2.getCipher(minerKey);
		publicForGuessDecrypt[1] = ((AdditiveElgamalCiphertext) passwordGuessCipherBlinded).getEphemeral(minerKey);
		
		BigInteger[] secretsForGuessDecrypt = new BigInteger[2];

		secretsForGuessDecrypt[0] = minerKey.generateEphemeral(rand);
		secretsForGuessDecrypt[1] = newKey.getPrivKey()[0];

		CryptoData[] envForGuessDecrypt = new CryptoData[2];
		envForGuessDecrypt[0] = new ECCurveData(curve, curve.decodePoint(voterKey.getPublicKey()));
		envForGuessDecrypt[1] = new ECPointData(g);

		fullProofDataUnpacked[0][4] = new CryptoDataArray(publicForGuessDecrypt);
		fullProofDataUnpacked[1][4] = new CryptoDataArray(secretsForGuessDecrypt);
		fullProofDataUnpacked[2][4] = new CryptoDataArray(envForGuessDecrypt);
		for(int i = 0; i < 3; i++) {
			fullProofData[i] = new CryptoDataArray(fullProofDataUnpacked[i]);
		}
		//Create hash of all relevant components to sign using given key image.
	}

	private ZKPProtocol getVoterProof(SourceTransaction[] ringMembers, AdditiveElgamalPubKey minerKey) {
		ZKPProtocol[] validTransactionInner = new ZKPProtocol[5];
		
		//Create proof for one transaction on step 10a
		ZKPProtocol[] proofOfMatchingInner = new ZKPProtocol[3];
		//Proof of first bulletpoint is essentially cipher - key is a DHH with ephemeral
		//Proof of second and third bullet points are proofs of rerandomization:  cipher1 - cipher2, then DHH
		proofOfMatchingInner[0] = proofOfMatchingInner[1] = proofOfMatchingInner[2] = minerKey.getZKPforRerandomization();

		ZKPProtocol proofOfMatching = new ZeroKnowledgeAndProver(proofOfMatchingInner);
		
		ZKPProtocol[] ringPortionInner = new ZKPProtocol[ringMembers.length];
		for(int i = 0; i < ringPortionInner.length; i++) {
			ringPortionInner[i] = proofOfMatching;
		}
		validTransactionInner[0] = new ZeroKnowledgeOrProver(ringPortionInner, minerKey.getOrder());
		
		//Create proof for step b
		validTransactionInner[1] = new ECDummyBallot10bProver();
		//Create proof for step c
		validTransactionInner[2] = new ECEqualDiscreteLogsForAnyNumberProver(4);
		//Create proof for step d:
		validTransactionInner[3] = new ECDummyBallot10dProver();
		//Create proof for step e:
		validTransactionInner[4] = validTransactionInner[2];
		
		
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
	public void adjustForPassword(Additive_Priv_Key minerKey, ObjectInputStream[] in, ObjectOutputStream[] out) {
		
	}



	@Override
	public boolean verifyTransaction(ProcessedBlockchain b) {
		// TODO Auto-generated method stub
		return false;
	}



	@Override
	public int getPosition() {
		return position;
	}



	@Override
	public void setPosition(int position) {
		this.position = position;
	}



	@Override
	public AdditiveCiphertext getDummyFlag() {
		// TODO Auto-generated method stub
		return null;
	}
	
}
