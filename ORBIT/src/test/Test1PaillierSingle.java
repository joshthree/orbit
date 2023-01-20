package test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

import blah.PaillierCiphertext;
import blah.PaillierPrivKey;
import blah.PaillierPubKey;
import election.EncryptedVote;
import election.Race;
import election.VoterDecision;
import election.singleCipherSVHNw.SVHNwRace;
import election.singleCipherSVHNw.SVHNwVoterDecision;

public class Test1PaillierSingle {
	public static void main(String arg[]) {
		
		SecureRandom rand = new SecureRandom("fhdjkghqeriupgyqhkdlvdjchlzvkcjxvbfiuhagperidfhgkhfdspogieqrjl".getBytes());
//		SecureRandom rand = new SecureRandom();
		PaillierPrivKey priv = new PaillierPrivKey(2048, rand); 
		int numCandidates = 4;
		System.out.println(priv);
		PaillierPubKey pub = (PaillierPubKey) priv.getPubKey();
		int bitSeparation = 33;
		Race race1 = new SVHNwRace(null, numCandidates, pub, bitSeparation);
		VoterDecision[] vote = new VoterDecision[numCandidates+1];
		for (int i = 0; i <= numCandidates; i++) {
			vote[i] = new SVHNwVoterDecision(i);
		}
//		EncryptedVote[] bigPsi = new EncryptedVote[numCandidates+1];
//		for (int i = 0; i <= numCandidates; i++) {
//			bigPsi[i] =  race1.vote(vote[i],rand);
//		}
//
//		for (int i = 0; i <= numCandidates; i++) {
//			System.out.printf("verify %d:  %s\n", i, race1.verify(bigPsi[i]));
//		}
		
		ArrayList<EncryptedVote> bigPsi2 = new ArrayList<EncryptedVote> ();
		long start1 = System.currentTimeMillis();
		for (int i = 0; i <= numCandidates; i++) {
			for(int j = 0; j <= i; j++) {
				bigPsi2.add(race1.vote(vote[i], rand)); 				
			}
		}
		EncryptedVote[] bigPsi3 = new EncryptedVote[bigPsi2.size()]; 
		int count = 0;
		for (int i = 0; i <= numCandidates; i++) {
			for(int j = 0; j <= i; j++) {
				bigPsi3[count] = race1.proveVote(bigPsi2.get(count), vote[i], rand); 	
				count++;
			}
		}

		long start2 = System.currentTimeMillis();
		boolean[] verify = new boolean[bigPsi2.size()];
		for (int i = 0; i < bigPsi3.length; i++) {
			verify[i] = race1.verify(bigPsi3[i]);
		}

		long end = System.currentTimeMillis();
		for (int i = 0; i < bigPsi2.size(); i++) {
			System.out.printf("verify %d:  %s\n", i, verify[i]);
		}
		System.out.println("Voting: " + bigPsi3.length + "  " + (start2-start1));

		System.out.println("Verifying:  " + (end-start2));
		race1.tally(bigPsi2, priv, null, null, rand);
		
		PaillierCiphertext cipher = new PaillierCiphertext(new BigInteger("17174998126114496078031322765574363470908471290988334784229298594715550043597115154823584383233416727468643282801830309614867621132450097434598399509735560484987915048832378013346267739459159683667011998510825851183435917844912343324026081028012393293087451608691085164549419670700995806116873172383475655504822125833090627046885024367755066018036529789306494450640790888736276627685205681785215739689707751792029527261092186501458458700895237152057739960661591993115610285880459534557496277770485672792113297781318578897633211865778982971550678222563962273799085830059495204770252859058264707129106468062013050371959431566188158149335733149869459418077351452676536827039896316200963373546176881255181737234589295029712956859346855923688155725396954774056815623089109022487134826974618843041201727642110973407389107538486273656650680253491819311212582304267997478499479353235728931227573948102845723768508053704344278285515350566898632778146624424537336511754483060349419934217088214962607011626294204286168850033197166240792018868599341301156884023356639598796634540472112525958292283396068733619802961630855803281123102336008320897702621861866383201026074313793906710592060722617667708730221277990688329291631319321080225884863776"));
		BigInteger rawResult = priv.decrypt(cipher).getValue(pub);
		System.out.println(rawResult);
		
		int[] result = new int[numCandidates];
		for(int i = 0; i < numCandidates; i++) {
			result[i] = rawResult.mod(BigInteger.TWO.pow(bitSeparation)).intValue();
			rawResult = rawResult.divide(BigInteger.TWO.pow(bitSeparation));
			
		}
		System.out.println(Arrays.toString(result));
		return;
	}
}
