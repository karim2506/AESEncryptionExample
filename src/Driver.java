import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Driver {

	static void fileProcessor(int cipherMode, String key, File inputFile, File outputFile) {
		try {
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

		} catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException
				| IllegalBlockSizeException | IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		String key = "SixteenBitsHash!";
		File inputFile = new File("src\\fileToEncrypt.txt");
		File encryptedFile = new File("src\\encryptedText.txt");
		File decryptedFile = new File("src\\decryptedText.txt");

		try {
			System.out.println("The initial file to Encrypt:");
			printContent("src\\fileToEncrypt.txt");
			Driver.fileProcessor(Cipher.ENCRYPT_MODE, key, inputFile, encryptedFile);
			System.out.println("The encrypted file:");
			printContent("src\\encryptedText.txt");
			Driver.fileProcessor(Cipher.DECRYPT_MODE, key, encryptedFile, decryptedFile);
			System.out.println("The decrypted file:");
			printContent("src\\decryptedText.txt");
		} catch (Exception ex) {
			System.out.println(ex.getMessage());
			ex.printStackTrace();
		}
	}
	
	public static void printContent(String filePath) {
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

}