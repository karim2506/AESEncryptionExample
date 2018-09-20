import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Driver {
	
	static String inputFileDirectory = "src\\fileToEncrypt.txt";
	static String encryptedFileDirectory = "src\\encryptedText.txt";
	static String decryptedFileDirectory = "src\\decryptedText.txt";
	static String hashedFileDirectory = "src\\hashedText.txt";

	private static void fileProcessor(int cipherMode, String key, File inputFile, File outputFile) throws Exception {
		Key secretKey = new SecretKeySpec(key.getBytes(), "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(cipherMode, secretKey);

		FileInputStream inputStream = new FileInputStream(inputFile);
		byte[] inputBytes = new byte[(int) inputFile.length()];
		inputStream.read(inputBytes);

		byte[] outputBytes = cipher.doFinal(inputBytes);

		FileOutputStream outputStream = new FileOutputStream(outputFile);
		outputStream.write(outputBytes);

		inputStream.close();
		outputStream.close();
	}
	
	private static void printContent(String filePath) {
		try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
			   String line = null;
			   while ((line = br.readLine()) != null) {
			       System.out.println(line);
			   }
			} catch (IOException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
			}
	}
	
	private static String hashFile(String filePath) throws Exception {
		MessageDigest md = MessageDigest.getInstance("MD5");
	    md.update(Files.readAllBytes(Paths.get(filePath)));
	    byte[] digest = md.digest();
	    
	    String hash = DatatypeConverter
	      .printHexBinary(digest).toUpperCase();
	    
	    FileOutputStream outputStream = new FileOutputStream(hashedFileDirectory);
		outputStream.write(hash.getBytes());
		outputStream.close();
	    
	    return hash;
	}
	
	public static String sign(String plainText, PrivateKey privateKey) throws Exception {
	    Signature privateSignature = Signature.getInstance("SHA256withRSA");
	    privateSignature.initSign(privateKey);
	    privateSignature.update(plainText.getBytes());

	    byte[] signature = privateSignature.sign();

	    return Base64.getEncoder().encodeToString(signature);
	}
	
	private static KeyPair generateKeyPair() throws Exception {
	    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
	    generator.initialize(2048, new SecureRandom());
	    KeyPair pair = generator.generateKeyPair();

	    return pair;
	}
	
	private static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
	    Signature publicSignature = Signature.getInstance("SHA256withRSA");
	    publicSignature.initVerify(publicKey);
	    publicSignature.update(plainText.getBytes());

	    byte[] signatureBytes = Base64.getDecoder().decode(signature);

	    return publicSignature.verify(signatureBytes);
	}

	public static void main(String[] args) throws Exception {
		String key = "SixteenBytesKey!";
		File inputFile = new File(inputFileDirectory);
		File encryptedFile = new File(encryptedFileDirectory);
		File decryptedFile = new File(decryptedFileDirectory);
		File hashedFile = new File(hashedFileDirectory);
		
//		KeyPair pair = generateKeyPair();
//		String signature = sign("foobar", pair.getPrivate());
//		//Let's check the signature
//		boolean isCorrect = verify("foobar", signature, pair.getPublic());
//		System.out.println("Signature correct: " + isCorrect);

		System.out.println("The initial file to Encrypt:");
		printContent(inputFileDirectory);
		
		System.out.println("The hash of the file:");
		System.out.println(hashFile(inputFileDirectory));
		
		Driver.fileProcessor(Cipher.ENCRYPT_MODE, key, hashedFile, encryptedFile);
		System.out.println("The encrypted file:");
		printContent(encryptedFileDirectory);
		
		Driver.fileProcessor(Cipher.DECRYPT_MODE, key, encryptedFile, decryptedFile);
		System.out.println("The decrypted file:");
		printContent(decryptedFileDirectory);
	}
}