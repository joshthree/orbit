package blah;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import zero_knowledge_proofs.ZKToolkit;

public class AdditiveElgamalPrivKey implements Additive_Priv_Key {
	private BigInteger privKey;
	private ECPoint g;
	private ECPoint y;
	private AdditiveElgamalPubKey pub;
	
	public AdditiveElgamalPrivKey(ECPoint g, SecureRandom rand) {
		this.g = g;
		this.privKey = ZKToolkit.random(g.getCurve().getOrder(), rand);
		this.y = g.multiply(privKey);
		pub = new AdditiveElgamalPubKey(g, y);
	}
	public AdditiveElgamalPrivKey(BigInteger privKey, ECPoint g) {
		this.privKey = privKey;
		this.g = g;
		this.y = g.multiply(privKey);
		pub = new AdditiveElgamalPubKey(g, y);
	}
	
	@Override
	public AdditiveElgamalPubKey getPubKey() {
		// TODO Auto-generated method stub
		return pub;
	} 

	@Override
	public BigInteger[] getPrivKey() {
		return new BigInteger[] {privKey};
	}

	@Override
	public AdditiveElgamalCiphertext decrypt(Ciphertext cipher) {
		AdditiveElgamalCiphertext cipher2 = (AdditiveElgamalCiphertext) cipher;
		ECPoint newCipher = ((ECPoint) cipher2.getCipher(pub)).add(cipher2.getEphemeral(pub).multiply(privKey.negate()));
		return new AdditiveElgamalCiphertext(newCipher, cipher2.getEphemeral(pub));
	}
	
	public AdditiveElgamalCiphertext addKey(Ciphertext cipher) {
		AdditiveElgamalCiphertext cipher2 = (AdditiveElgamalCiphertext) cipher;
		ECPoint newCipher = ((ECPoint) cipher2.getCipher(pub)).add(cipher2.getEphemeral(pub).multiply(privKey));
		return new AdditiveElgamalCiphertext(newCipher, cipher2.getEphemeral(pub));
	}

	@Override
	public AdditiveElgamalCiphertext partialGroupDecrypt(Ciphertext c, Channel[] channels) {
		// TODO Auto-generated method stub
		return null;
	}



}
