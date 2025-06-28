package com.template.util;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAUtil {

	public static String DIR = "D:\\";

	public static KeyPairGenerator KEYPAIRGENERATOR = null;
	static KeyFactory KEYFACTORY;

//	static String PADDING = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" ;
	static String PADDING = "RSA/ECB/PKCS1Padding" ;
	
	static {
		try {
//			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());			
//			KEYPAIRGENERATOR = KeyPairGenerator.getInstance("RSA","BC");
			KEYPAIRGENERATOR = KeyPairGenerator.getInstance("RSA");
			KEYPAIRGENERATOR.initialize(4096);
//			KEYFACTORY = KeyFactory.getInstance("RSA", "BC");
			KEYFACTORY = KeyFactory.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public static KeyPair generateKeyPair () throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        return keyGen.generateKeyPair();		
	}
	
	public static void main(String[] args) throws Exception {
		KeyPair pair = KEYPAIRGENERATOR.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		// converting byte to String
		String sPublicKey = RSAPublicKeyUtil.toString(publicKey);
		String sPrivateKey = RSAPrivateKeyUtil.toString(privateKey);

		System.out.println("Public Key " + sPublicKey);
		System.out.println("Private Key " + sPrivateKey);

		// converting it back to public key
		PublicKey publicKey2 = RSAPublicKeyUtil.generateFromString(sPublicKey);
		PrivateKey privateKey2 = RSAPrivateKeyUtil.generateFromString(sPrivateKey);

//		System.out.println("FINAL PUBLIC KEY " + publicKey2.toString());
//		System.out.println("FINAL PRIVATE KEY " + privateKey2.toString());
	
		System.out.println("Public key format: " + publicKey.getFormat());
		System.out.println("Private key format: " + privateKey.getFormat());
		
		String sEncrypted1 = RSAPublicKeyUtil.encrypt("This is the message that needs to be encrypted", publicKey);
		System.out.println("Encrypted: " + sEncrypted1);
		
		String sDecrypted1 = RSAPrivateKeyUtil.decrypt(sEncrypted1, privateKey);
		System.out.println("Decrypted: " + sDecrypted1);		
	
	}

} 