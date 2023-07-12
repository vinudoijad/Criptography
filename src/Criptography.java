import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Criptography {
	
	  public static void main(String[] args) {
	        try {
	            String plaintext = "Vinayak";
	            String secretKey = "thisisasecretkey";

	            // Encryption
	            byte[] encryptedText = encrypt(plaintext, secretKey);
	            System.out.println("Encrypted Text: " + bytesToHexString(encryptedText));

	            // Decryption
	            String decryptedText = decrypt(encryptedText, secretKey);
	            System.out.println("Decrypted Text: " + decryptedText);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	    }

	    public static byte[] encrypt(String plaintext, String secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
	            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
	        return cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
	    }

	    public static String decrypt(byte[] encryptedText, String secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
	            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
	        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
	        Cipher cipher = Cipher.getInstance("AES");
	        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
	        byte[] decryptedBytes = cipher.doFinal(encryptedText);
	        return new String(decryptedBytes, StandardCharsets.UTF_8);
	    }

	    public static String bytesToHexString(byte[] bytes) {
	        StringBuilder sb = new StringBuilder();
	        for (byte b : bytes) {
	            sb.append(String.format("%02X", b));
	        }
	        return sb.toString();
	    }
	}


