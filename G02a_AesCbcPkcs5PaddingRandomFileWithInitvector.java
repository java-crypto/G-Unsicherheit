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

import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class G02a_AesCbcPkcs5PaddingRandomFileWithInitvector {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, FileNotFoundException, IOException {
		System.out.println("G02a AES im Betriebsmodus CBC PKCS5Padding mit Zufalls-Initvektor mit einer Datei und Infile-Initvector - nur verschlüsseln");
		// es werden ein paar variablen benötigt:
		String dateinameReadString = "g02_test.txt"; // aus der datei wird das plaintextByte eingelesen
		String dateinameWriteString = "g02_test.enc"; // in diese datei wird das ciphertextByte geschrieben

		String plaintextString = ""; // die daten werden aus der datei gelesen
		byte[] plaintextByte = null; // die daten werden aus der datei gelesen

		// zuerst testen wir ob die einzulesende datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};

		// datei in byte array einlesen
		plaintextByte = readBytesFromFileNio(dateinameReadString);
		plaintextString = new String(plaintextByte, "UTF-8"); // die umwandlung erfolgt nur zur späteren anzeige

		// diese konstanten und variablen benötigen wir zur ver- und entschlüsselung
		// der schlüssel ist exakt 32 zeichen lang und bestimmt die stärke der
		// verschlüsselung
		// mögliche schlüssellängen sind 16 byte (128 bit), 24 byte (192 bit) und 32
		// byte (256 bit)
		// final byte[] keyByte = "1234567890123456".getBytes("UTF-8"); // 16 byte
		final byte[] keyByte = "12345678901234567890123456789012".getBytes("UTF-8"); // 32 byte
		// der initialisierungsvektor ist exakt 16 zeichen lang
		byte[] initvectorByte = new byte[16];
		SecureRandom secureRandom = new SecureRandom();
		secureRandom.nextBytes(initvectorByte);

		// der verschluesselte (encrypted) text kommt in diese variable in form eines
		// byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt

		// ab hier arbeiten wir nun im verschlüsselungsmodus
		// umwandlung des klartextes in ein byte array
		plaintextByte = plaintextString.getBytes("UTF-8");
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = AesCbcPaddingEncrypt(plaintextByte, keyByte, initvectorByte);

		// byte array in eine datei schreiben
		try (DataOutputStream out = new DataOutputStream(new FileOutputStream(dateinameWriteString))) {
			out.writeInt(initvectorByte.length);
			out.write(initvectorByte);
			out.writeInt(ciphertextByte.length);
			out.write(ciphertextByte);
		}

		System.out.println("");
		System.out.println("Klartextdaten einlesen und als verschlüsselte Datei speichern");
		System.out.println("keyByte (hex)            :" + DatatypeConverter.printHexBinary(keyByte));
		System.out.println("initvectorByte (hex)     :" + DatatypeConverter.printHexBinary(initvectorByte));
		System.out.println("Dateiname Lesen          :" + dateinameReadString);
		System.out.println("Dateiname Schreiben      :" + dateinameWriteString);
		System.out.println("plaintextByte (hex)      :" + DatatypeConverter.printHexBinary(plaintextByte));
		System.out.println("plaintextString          :" + plaintextString);
		System.out.println("= = = Verschlüsselung = = =");
		System.out.println("initvectorByte File (hex):" + DatatypeConverter.printHexBinary(initvectorByte));
		System.out.println("ciphertextByte (hex)     :" + DatatypeConverter.printHexBinary(ciphertextByte));
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

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
	}

	private static byte[] readBytesFromFileNio(String filenameString) {
		byte[] byteFromFileByte = null;
		try {
			byteFromFileByte = Files.readAllBytes(Paths.get(filenameString));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return byteFromFileByte;
	}
}
