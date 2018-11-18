package net.bplaced.javacrypto.unsecure;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* Datum/Date (dd.mm.jjjj): 15.11.2018 
* Funktion: liest eine bild datei und verschlüsselt sie im aes ecb modus kein padding
*           zum vergleich wird dieselbe datei im aes modus cbc kein padding verschlüsselt
* Function: encrypts a picture file using aes ecb modus without padding
*           for comparison reasons the same file gets encrypted using aes modus cbc without padding
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class G01_AesEcbPenguin {

	public static void main(String[] args) throws Exception {

		System.out.println("G01 ECB Pinguin");

		// es werden ein paar variablen benötigt:
		String dateinameReadString = "g01_tux.bmp"; // aus der datei wird das plaintextByte eingelesen
		byte[] ciphertextEcbByte = null; // das byte array nimmt die ecb-verschlüsselten bild-daten auf
		String dateinameWriteEcbString = "g01_tux_ecb.bmp"; // in diese datei wird das ciphertextByte geschrieben
		byte[] ciphertextCbcByte = null; // das byte array nimmt die cbv-verschlüsselten bild-daten auf
		String dateinameWriteCbcString = "g01_tux_cbc.bmp"; // in diese datei wird das ciphertextByte geschrieben

		// sowohl das keyByte als auch das initvectorByte werden hier fest eingestellt
		// und sind für die weitere darstellung nicht von belang
		final byte[] keyByte = "12345678901234567890123456789012".getBytes("UTF-8");
		final byte[] initvectorByte = "abcdefghijklmnop".getBytes("UTF-8");

		// starten wir nun mit dem programmablauf

		// zuerst testen wir ob die einzulesende datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};

		// wir öffnen die original bild datei
		FileInputStream fileInputStream = new FileInputStream(dateinameReadString);
		// wir lesen einen teil des headers der bmp-datei ein
		int HEADER_LENGTH = 14; // 14 byte bmp header
		byte headerByte[] = new byte[HEADER_LENGTH];
		fileInputStream.read(headerByte, 0, HEADER_LENGTH);
		// nun lesen wir den zweiten teil des bmp-headers ein
		int INFO_HEADER_LENGTH = 40; // 40-byte bmp info header
		byte infoheaderByte[] = new byte[INFO_HEADER_LENGTH];
		fileInputStream.read(infoheaderByte, 0, INFO_HEADER_LENGTH);
		// nun wird die eigentlichen bilddaten eingelesen, welche später verschlüsselt
		// werden
		byte[] bmpContentByte = new byte[fileInputStream.available()];
		fileInputStream.read(bmpContentByte);
		fileInputStream.close();

		// verschlüsselung mittels ecb modus
		ciphertextEcbByte = new byte[bmpContentByte.length];
		ciphertextEcbByte = AesEcbPaddingEncrypt(bmpContentByte, keyByte);
		// es werden nun die unverschlüsselten headerByte und infoheaderByte
		// gespeichert, gefolgt vom ecb-verschlüsselten ciphertextEcbByte
		writeBmpToFile(dateinameWriteEcbString, headerByte, infoheaderByte, ciphertextEcbByte);
		
		// verschlüsselung mittels cbc modus
		ciphertextCbcByte = new byte[bmpContentByte.length];
		ciphertextCbcByte = AesCbcNopaddingEncrypt(bmpContentByte, keyByte, initvectorByte);
		// es werden nun die unverschlüsselten headerByte und infoheaderByte
		// gespeichert, gefolgt vom cbc-verschlüsselten ciphertextCbcByte
		writeBmpToFile(dateinameWriteCbcString, headerByte, infoheaderByte, ciphertextCbcByte);
		
		System.out.println("");
		System.out.println("Dateiname Lesen Original:" + dateinameReadString);
		System.out.println("Dateiname Schreiben ECB :" + dateinameWriteEcbString);
		System.out.println("Dateiname Schreiben CBC :" + dateinameWriteCbcString);
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
	}
	
	public static byte[] AesEcbPaddingEncrypt(byte[] plaintextByte, byte[] keyByte)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] ciphertextByte = null;
		// der schlüssel wird in die richtige form gebracht
		SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
		// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
		Cipher aesCipherEnc = Cipher.getInstance("AES/ECB/NOPADDING");
		// nun wird die routine mit dem schlüssel initialisiert
		aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec);
		// hier erfolgt nun die verschlüsselung des plaintextes
		ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
		return ciphertextByte;
	}

	public static byte[] AesCbcNopaddingEncrypt(byte[] plaintextByte, byte[] keyByte, byte [] initvectorByte) throws NoSuchAlgorithmException, NoSuchPaddingException, 
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
					byte[] ciphertextByte = null;
					// der schlüssel wird in die richtige form gebracht
					SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
					// der initvector wird in die richtige form gebracht
					IvParameterSpec ivKeySpec = new IvParameterSpec(initvectorByte);
					// die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
					Cipher aesCipherEnc = Cipher.getInstance("AES/CBC/NOPADDING");
					// nun wird die routine mit dem schlüssel initialisiert
					aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec, ivKeySpec);
					// hier erfolgt nun die verschlüsselung des plaintextes
					ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
					return ciphertextByte;
				}

	public static void writeBmpToFile(String filenameString, byte[] headerByte, byte[] infoheaderByte,
			byte[] bmpContentByte) throws Exception {
		FileOutputStream fileOutputStream = new FileOutputStream(filenameString);
		fileOutputStream.write(headerByte);
		fileOutputStream.write(infoheaderByte);
		fileOutputStream.write(bmpContentByte);
		fileOutputStream.flush();
		fileOutputStream.close();
	}
}
