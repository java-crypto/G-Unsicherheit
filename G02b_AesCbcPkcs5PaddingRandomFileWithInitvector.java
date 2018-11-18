package net.bplaced.javacrypto.unsecure;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 18.11.2018 
* Funktion: liest eine datei und verschlüsselt sie im aes cbc modus pkcs5 padding
*           speicherung des initvector in der verschluesselten datei
*           basiert auf B09c_AesCbcPkcs5PaddingRandomFileWithInitvector
* Function: encrypts a file using aes cbc modus with pkcs5 padding
*           saves the initvector in the encrypted file 
*			is based on B09c_AesCbcPkcs5PaddingRandomFileWithInitvector
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class G02b_AesCbcPkcs5PaddingRandomFileWithInitvector {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, FileNotFoundException, IOException {
		System.out.println(
				"G02b AES im Betriebsmodus CBC PKCS5Padding mit Zufalls-Initvektor mit einer Datei und Infile-Initvector nur Entschlüsseln");
		// es werden ein paar variablen benötigt:
		String decryptedtextString = ""; // enthält später den entschlüsselten text

		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung
		// der schlüssel ist exakt 32 zeichen lang und bestimmt die stärke der
		// verschlüsselung
		// mögliche schlüssellängen sind 16 byte (128 bit), 24 byte (192 bit) und 32
		// byte (256 bit)
		// final byte[] keyByte = "1234567890123456".getBytes("UTF-8"); // 16 byte
		final byte[] keyByte = "12345678901234567890123456789012".getBytes("UTF-8"); // 32 byte
		// der initialisierungsvektor ist exakt 16 zeichen lang
		byte[] initvectorByte = new byte[16];
		// der verschluesselte (encrypted) text kommt in diese variable in form eines
		// byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt

		// der entschlüsselte (decrypted) text kommt in dieses byte array, welches
		// später in einen string umkodiert wird
		byte[] decryptedtextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes
											// abhängt
		// ab hier arbeiten wir nun im entschlüsselungsmodus
		// wir starten die entschlüsselung mit einem leeren ciphertext
		ciphertextByte = null;
		// ebenso ist der initvector leer - wird auch aus der datei gelesen
		initvectorByte = null;

		// byte array einlesen
		String dateinameReadString = "g02_test.enc"; // ciphertextByte lesen
		String dateinameWriteString = "g02_test.dec"; // decryptedtextByte schreiben

		// zuerst testen wir ob die einzulesende datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};

		// das ciphertextByte wird aus der datei gelesen
		try (DataInputStream dataIn = new DataInputStream(new FileInputStream(dateinameReadString))) {
			int initvectorSize = dataIn.readInt();
			initvectorByte = new byte[initvectorSize];
			dataIn.read(initvectorByte, 0, initvectorSize);
			int ciphertextSize = dataIn.readInt();
			ciphertextByte = new byte[ciphertextSize];
			dataIn.read(ciphertextByte, 0, ciphertextSize);
		}

		// nun wird der ciphertext wieder entschlüsselt
		decryptedtextByte = AesCbcPaddingDecrypt(ciphertextByte, keyByte, initvectorByte);

		// wir schreiben die entschlüsselten daten in eine datei
		writeBytesToFileNio(decryptedtextByte, dateinameWriteString);

		// zurück-kodierung des byte array in text
		decryptedtextString = new String(decryptedtextByte, "UTF-8");

		// ausgabe der variablen
		System.out.println("");
		System.out.println("keyByte (hex)            :" + DatatypeConverter.printHexBinary(keyByte));
		System.out.println("Dateiname Lesen          :" + dateinameReadString);
		System.out.println("Dateiname Schreiben      :" + dateinameWriteString);
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("initvectorByte File (hex):" + DatatypeConverter.printHexBinary(initvectorByte));
		System.out.println("ciphertextByte (hex)     :" + DatatypeConverter.printHexBinary(ciphertextByte));
		System.out.println("= = = Entschlüsselung = = =");
		System.out.println("decryptedtextByte (hex)  :" + DatatypeConverter.printHexBinary(decryptedtextByte));
		System.out.println("decryptedtextString      :" + decryptedtextString);
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
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] decryptedtextByte = null;
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// der initvector wird in die richtige form gebracht
		IvParameterSpec ivKeySpec = new IvParameterSpec(initvectorByte);
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherDec = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec, ivKeySpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		decryptedtextByte = aesCipherDec.doFinal(ciphertextByte);
		return decryptedtextByte;
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
	}

	private static void writeBytesToFileNio(byte[] byteToFileByte, String filenameString) {
		try {
			Path path = Paths.get(filenameString);
			Files.write(path, byteToFileByte);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
