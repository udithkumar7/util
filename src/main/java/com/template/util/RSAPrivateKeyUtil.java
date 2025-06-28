package com.template.util;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAPrivateKeyUtil {
	public static PrivateKey generateFromString(String sPrivateKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] bPrivateKey = Base64.getDecoder().decode(sPrivateKey);
		return RSAUtil.KEYFACTORY.generatePrivate(new PKCS8EncodedKeySpec(
				bPrivateKey));
	}

	// Decrypt using privatekey
	public static String decrypt(String encryptedText, String privatekey)
			throws Exception {
		return decrypt(encryptedText, generateFromString(privatekey));
	}

	public static String decrypt(String encryptedText, PrivateKey privatekey)
			throws Exception {
		System.out.println("RSA Decryption - Using padding: " + RSAUtil.PADDING);
		System.out.println("RSA Decryption - Encrypted text length: " + encryptedText.length());
		
		Cipher cipher = Cipher
				.getInstance(RSAUtil.PADDING);
		cipher.init(Cipher.DECRYPT_MODE, privatekey);
		
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
		System.out.println("RSA Decryption - Decoded bytes length: " + encryptedBytes.length);
		
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		String result = new String(decryptedBytes);
		System.out.println("RSA Decryption - Decrypted result length: " + result.length());
		
		return result;
	}

	public static String toString(PrivateKey privateKey) {
		byte[] bPrivateKey = privateKey.getEncoded();
		return Base64.getEncoder().encodeToString(bPrivateKey);
	}
} 