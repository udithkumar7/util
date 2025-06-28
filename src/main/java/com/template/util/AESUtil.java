package com.template.util;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

//	static String CIPHER = "AES/ECB/PKCS5Padding";
	static String CIPHER = "AES/CBC/PKCS5Padding";
	
	static String DIGEST = "SHA-256";
//	static String DIGEST = "SHA-512";
	
	static String ALGORITHM = "AES";

    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
	
	public static void main(String[] args) throws Exception {

		String secretKey = "ABCDEFGHIJKLMNOP";
		String originalString = "success";

		String encryptedString = encrypt(originalString, secretKey);
		String decryptedString = decrypt(encryptedString, secretKey);

		System.out.println("Original String:" + originalString);
		System.out.println("Encrypted value:" + encryptedString);
//		System.out.println("Base64 Encoded key " + Base64.getEncoder().encodeToString(secretKey.getBytes()));
	}

	// method to encrypt the secret text using key
	public static String encrypt(String strToEncrypt, String myKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		MessageDigest sha = MessageDigest.getInstance(DIGEST);
		Cipher cipher = Cipher.getInstance(CIPHER);
		byte[] iv = new byte[IV_LENGTH_BYTE];
		
		byte[] key = myKey.getBytes(StandardCharsets.UTF_8);
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16);
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec,
				new GCMParameterSpec(TAG_LENGTH_BIT, iv));
		byte[] tst = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(tst);
	}
	
	// method to decrypt the secret text using key
	public static String decrypt(String strToDecrypt, String myKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		MessageDigest sha = MessageDigest.getInstance(DIGEST);
		Cipher cipher = Cipher.getInstance(CIPHER);
		byte[] iv = new byte[IV_LENGTH_BYTE];
		
		byte[] key = myKey.getBytes(StandardCharsets.UTF_8);
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16);
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, ALGORITHM);
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec,
				new GCMParameterSpec(TAG_LENGTH_BIT, iv));
		byte[] tst = Base64.getDecoder().decode(strToDecrypt);
		return new String(cipher.doFinal(tst));
	}
	
    public static String encryptJS(String data, String secretKey) throws Exception {
        // Convert hex string to bytes and use first 16 bytes as IV
        byte[] keyBytes = hexStringToByteArray(secretKey);
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyBytes, 0, ivBytes, 0, Math.min(keyBytes.length, 16));
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);

        byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    public static String decryptJS(String encryptedText, String secretKey) throws Exception {
        // Convert hex string to bytes and use first 16 bytes as IV
        byte[] keyBytes = hexStringToByteArray(secretKey);
        byte[] ivBytes = new byte[16];
        System.arraycopy(keyBytes, 0, ivBytes, 0, Math.min(keyBytes.length, 16));
        
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);

        byte[] decodedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        return new String(decryptedBytes, "UTF-8");
    }
    
    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
} 