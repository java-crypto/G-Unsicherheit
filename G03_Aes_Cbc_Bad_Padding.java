package net.bplaced.javacrypto.unsecure;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 24.09.2019
* Funktion: Padding Orakel - Basisversion
* Function: Padding Oracle - basics
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import javax.crypto.spec.SecretKeySpec;

public class G03_Aes_Cbc_Bad_Padding {

	public static void main(String[] args) throws Exception {
		System.out.println("G03 AES CBC Bad Padding");

		// basisroutinen aus B07b_AesCbcPkcs5PaddingString.java
		// es werden ein paar variablen benötigt:
		String plaintextString = "HalloWelt012345"; // hier 15 zeichen
		String decryptedtextString = ""; // enthält später den entschlüsselten text

		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung

		// der schlüssel ist exakt 32 zeichen lang und bestimmt die stärke der
		// verschlüsselung
		// hier ist der schlüssel 32 byte = 256 bit lang
		// mögliche schlüssellängen sind 16 byte (128 bit), 24 byte (192 bit) und 32
		// byte (256 bit)
		// final byte[] keyByte = "1234567890123456".getBytes("UTF-8"); // 16 byte
		final byte[] keyByte = "12345678901234567890123456789012".getBytes("UTF-8"); // 32 byte
		// der initialisierungsvektor ist exakt 16 zeichen lang
		final byte[] initvectorByte = "abcdefghijklmnop".getBytes("UTF-8");

		byte[] plaintextByte = null;
		// der verschluesselte (encrypted) text kommt in diese variable in form eines
		// byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt
		// der entschlüsselte (decrypted) text kommt in dieses byte array, welches
		// später in einen string umkodiert wird
		byte[] decryptedtextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes
											// abhängt

		// ab hier arbeiten wir nun im verschlüsselungsmodus
		// umwandlung des klartextes in ein byte array
		plaintextByte = plaintextString.getBytes("UTF-8");
		ciphertextByte = AesCbcPaddingEncrypt(plaintextByte, keyByte, initvectorByte);

		// ab hier arbeiten wir nun im entschlüsselungsmodus
		// nun wird der ciphertext wieder entschlüsselt
		decryptedtextByte = AesCbcPaddingDecrypt(ciphertextByte, keyByte, initvectorByte);
		// zurück-kodierung des byte array in text
		decryptedtextString = new String(decryptedtextByte, "UTF-8");
		// ausgabe der variablen
		System.out.println("");
		System.out.println("keyByte (hex)          :" + printHexBinary(keyByte));
		System.out.println("initvectorByte (hex)   :" + printHexBinary(initvectorByte));
		System.out.println("plaintextString        :" + plaintextString);
		System.out.println("plaintextByte (hex)    :" + printHexBinary(plaintextByte));
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);

		// veränderung des ciphertextbyte
		System.out.println("\nVeränderung des ciphertextByte");
		ciphertextByte[15] = 0;

		// ab hier arbeiten wir nun im entschlüsselungsmodus
		// nun wird der ciphertext wieder entschlüsselt
		decryptedtextByte = AesCbcPaddingDecrypt(ciphertextByte, keyByte, initvectorByte);
		// zurück-kodierung des byte array in text
		decryptedtextString = new String(decryptedtextByte, "UTF-8");
		// ausgabe der variablen
		System.out.println("ciphertextByte (hex)   :" + printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex):" + printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString    :" + decryptedtextString);
	}

	public static byte[] AesCbcPaddingEncrypt(byte[] plaintextByte, byte[] keyByte, byte[] initvectorByte)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] ciphertextByte = null;
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// der initvector wird in die richtige form gebracht
		IvParameterSpec ivKeySpec = new IvParameterSpec(initvectorByte);
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec, ivKeySpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static byte[] AesCbcPaddingDecrypt(byte[] ciphertextByte, byte[] keyByte, byte[] initvectorByte)
			throws UnsupportedEncodingException {
		byte[] decryptedtextByte = null;
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// der initvector wird in die richtige form gebracht
		IvParameterSpec ivKeySpec = new IvParameterSpec(initvectorByte);
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherDec = null;
		try {
			aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		} catch (NoSuchAlgorithmException e) {
			decryptedtextByte = "Exception: NoSuchAlgorithmException".getBytes("UTF-8");
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			decryptedtextByte = "Exception: NoSuchPaddingException".getBytes("UTF-8");
			e.printStackTrace();
		}
		// nun wird die routine mit dem schlüssel initialisiert
		try {
			aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec, ivKeySpec);
		} catch (InvalidKeyException e) {
			decryptedtextByte = "Exception: InvalidKeyException".getBytes("UTF-8");
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			decryptedtextByte = "Exception: InvalidAlgorithmParameterException".getBytes("UTF-8");
			e.printStackTrace();
		}
		// hier erfolgt nun die entschlüsselung des ciphertextes
		try {
			decryptedtextByte = aesCipherDec.doFinal(ciphertextByte);
		} catch (IllegalBlockSizeException e) {
			decryptedtextByte = "Exception: IllegalBlockSizeException".getBytes("UTF-8");
			e.printStackTrace();
		} catch (BadPaddingException e) {
			decryptedtextByte = "Exception: BadPaddingException".getBytes("UTF-8");
			// e.printStackTrace();
		}
		return decryptedtextByte;
	}

	public static String printHexBinary(byte[] bytes) {
		final char[] hexArray = "0123456789ABCDEF".toCharArray();
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
}