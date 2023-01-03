import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;


public class CreateBallotTransaction {
	
	int ballotPlaintext; //don't want to encrypt in ballot transaction creation, use ciphertext as input
	int dummyFlag; //elgamal ciphertext, look into zkprover
	int dummyPassword; //elgamal ciphertext
	int ringSignature; //own object/class
	
	public CreateBallotTransaction(int plaintext) {
		ballotPlaintext = plaintext; // implement dummy protocol part 1 in constructor
	}
	
	public exponentialElgamalCiphertext encryptBallot(int plaintext, BigInteger publicKey, BigInteger generator, int randomness, BigInteger hid) {
		BigInteger ephemeralKey = generator.pow(randomness);
		BigInteger message = (hid.pow(randomness)).multiply(generator.pow(plaintext));
		exponentialElgamalCiphertext encryptedBallot = new exponentialElgamalCiphertext(BigInteger.valueOf(1),BigInteger.valueOf(1));
		encryptedBallot.ephemeralKey = ephemeralKey;
		encryptedBallot.message = message;
		return encryptedBallot;
	}
	
	public static genKeyPair gen_key_pair() {
		genKeyPair signKey = new genKeyPair(1,1,1);
	    return signKey;
	}


	public static genPublicKey gen_public_key() {
		
	    genPublicKey ringKey = new genPublicKey(1,1);
	    return ringKey;
	}
	
	public List<Object> sign(String msg, genKeyPair signer_key_pair, List<genPublicKey> other_public_keys) {
	    int ring_size = other_public_keys.size() + 1;
	    int key = msg.hashCode();
	    Random rand = new Random(); //instance of random class
	    int u = rand.nextInt((int) ((Math.pow(2, 1023)) + 1));
	    List<Integer> v;
	    for (int i = 0; i < ring_size; i++) {
	    	  v.add(0);
	    	}
	    
	    v.set(0, String.valueOf(u).hashCode()); //keyed_hash(key, u);
	    System.out.println(v);

	    List<Integer> s;
	    s.add(0);
	    for (int i = 0; i < ring_size; i++) {
	    	  s.add(rand.nextInt((int) ((Math.pow(2, 1023)) + 1)));
	    	}
	    for (int i = 0; i < ring_size; i++) {
	    	v.set(i, )
	        //v[i] = keyed_hash(key, xor(v[i - 1], rsa_encrypt_or_decrypt(s[i], other_public_keys[i - 1]['e'], other_public_keys[i - 1]['n'])))
	    //s[0] = rsa_encrypt_or_decrypt(xor(v[ring_size - 1], u), signer_key_pair['d'], signer_key_pair['n'])
	    }

	    List<Object> signature = {};
		signature.add("msg");
	    signature.add(signature);
	        'rows':
	            [{'e': signer_key_pair['e'], 'n': signer_key_pair['n'], 's': s[0]}] +
	            [{'e': other_public_keys[i - 1]['e'], 'n': other_public_keys[i - 1]['n'], 's': s[i]} for i in range(1, ring_size)]

	    # rotate signature randomly to conceal position of true signer
	    rotation = random.randint(0, ring_size - 1)
	    signature['v'] = rotate(v, rotation)[ring_size - 1]
	    signature['rows'] = rotate(signature['rows'], rotation)

	    return signature
	}
	
	public verify(signature) {
	    ring_size = len(signature['rows'])
	    key = crypto_hash(signature['msg'])
	    v = signature['v']
	    for i in range(0, ring_size):
	        row = signature['rows'][i]
	        v = keyed_hash(key, xor(v, rsa_encrypt_or_decrypt(row['s'], row['e'], row['n'])))
	    return v == signature['v']
	}
	
	public static void main(String[] args) {
				
		CreateBallotTransaction myTransaction = new CreateBallotTransaction(3);
		exponentialElgamalCiphertext ballotCiphertext = myTransaction.encryptBallot(1, BigInteger.valueOf(1), BigInteger.valueOf(1), 1, BigInteger.valueOf(1));
        System.out.println(ballotCiphertext);
        
        int ring_size = 10;
        
        genKeyPair signer_key_pair = gen_key_pair();
        List<genPublicKey> other_public_keys;
        
        for (int i = 0; i < ring_size; i++) {
        	other_public_keys.add(gen_public_key());
        }

        boolean signature = sign("hello world!", signer_key_pair, other_public_keys);
        System.out.println(signature);
        System.out.println("Verifies?", verify(signature));
    }
}
