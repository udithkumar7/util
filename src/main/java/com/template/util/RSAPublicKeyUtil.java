package com.template.util;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class RSAPublicKeyUtil {

	public static PublicKey generateFromString(String sPublicKey)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] bPublicKey = Base64.getDecoder().decode(sPublicKey);
		return RSAUtil.KEYFACTORY.generatePublic(new X509EncodedKeySpec(
				bPublicKey));
	}

	public static String encrypt(String plainText, String publickey)
			throws Exception {
		return encrypt(plainText, generateFromString(publickey));
	}

	public static String encrypt(String plainText, PublicKey publickey)
			throws Exception {
		Cipher cipher = Cipher
				.getInstance(RSAUtil.PADDING);
		cipher.init(Cipher.ENCRYPT_MODE, publickey);
		return Base64.getEncoder().encodeToString(
				cipher.doFinal(plainText.getBytes()));
	}

	public static String toString(PublicKey publicKey) {
		byte[] bPublicKey = publicKey.getEncoded();
		return Base64.getEncoder().encodeToString(bPublicKey);
	}
} 