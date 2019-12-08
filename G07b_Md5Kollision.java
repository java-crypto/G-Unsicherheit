package net.bplaced.javacrypto.unsecure;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenttext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 08.12.2019
* Funktion: errechnet die MD5-Hashwerte zweier Dateien
* Function: calculates the MD5-hashes of two files
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class G07b_Md5Kollision {

	public static void main(String[] args) throws Exception {
		System.out.println("G07b MD5 Kollision = Unsicherheit");
		System.out.println("Hinweis: nutzen Sie die MD5-Funktion niemals in Echtprogrammen da sie unsicher ist !");
		String filename1String = "g07b_plane.jpg";
		byte[] hash1Byte = generateMd5DoNotUse(filename1String);
		System.out.println("\nMD5-Hashwert der Datei: " + filename1String);
		System.out.println(
				"hash1Byte Länge:" + hash1Byte.length + " Data:" + printHexBinary(hash1Byte));
		String filename2String = "g07b_ship.jpg";
		byte[] hash2Byte = generateMd5DoNotUse(filename2String);
		System.out.println("MD5-Hashwert der Datei: " + filename2String);
		System.out.println(
				"hash2Byte Länge:" + hash2Byte.length + " Data:" + printHexBinary(hash2Byte));
		System.out.println("Die beiden MD5-Hashwerte sind gleich:" + Arrays.equals(hash1Byte, hash2Byte));
		
		System.out.println("\nAlternative Berechnung eines SHA-256-Hashwertes");
		hash1Byte = generateSha256(filename1String);
		System.out.println("\nSHA256-Hashwert der Datei:" + filename1String);
		System.out.println(
				"hash1Byte Länge:" + hash1Byte.length + " Data:" + printHexBinary(hash1Byte));
		hash2Byte = generateSha256(filename2String);
		System.out.println("SHA256-Hashwert der Datei:" + filename2String);
		System.out.println(
				"hash2Byte Länge:" + hash2Byte.length + " Data:" + printHexBinary(hash2Byte));
		System.out.println("Die beiden SHA256-Hashwerte sind gleich:" + Arrays.equals(hash1Byte, hash2Byte));
		
		System.out.println("\nG07b MD5 Kollision = Unsicherheit beendet");
	}

	public static byte[] generateMd5DoNotUse(String filenameString) throws IOException, NoSuchAlgorithmException {
		// bitte diese hashfunktion niemals in echtprogrammen nutzen
		// die hashfunktion ist unsicher
		// do not use this hashroutine in production
		// the hashroutine is unsecure
		File file = new File(filenameString);
		byte[] bufferByte = new byte[(int) file.length()];
		FileInputStream fis = new FileInputStream(file);
		fis.read(bufferByte);
		fis.close();
		MessageDigest md = MessageDigest.getInstance("MD5");
		md.update(bufferByte);
		return md.digest();
	}
	public static byte[] generateSha256(String filenameString) throws IOException, NoSuchAlgorithmException {
		File file = new File(filenameString);
		byte[] bufferByte = new byte[(int) file.length()];
		FileInputStream fis = new FileInputStream(file);
		fis.read(bufferByte);
		fis.close();
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(bufferByte);
		return md.digest();
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