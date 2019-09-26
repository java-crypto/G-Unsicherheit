package net.bplaced.javacrypto.unsecure;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 26.09.2019
* Projekt/Project: G04 DES Padding Orakel Setup / G04 Padding Oracle Setup
* Funktion: ermöglicht eigene Daten für das Padding Orakel
* Function: allows own data for the padding oracle
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion, 
* insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
* 
* Das Projekt basiert auf dem nachfolgenden Artikel:
* The project is based on this article:
* https://blog.skullsecurity.org/2013/a-padding-oracle-example
* 
*/

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class G04a_DesPaddingOracleSetup {

	public static void main(String[] args) throws Exception {
		System.out.println("G04a Setup für DES Padding Oracle");

		String PString = "Hello World";
		byte[] P = PString.getBytes("UTF-8");
		byte[] Padding = new byte[] { (byte) 0x05, (byte) 0x05, (byte) 0x05, (byte) 0x05, (byte) 0x05 };

		byte[] Pcomplete = new byte[P.length + Padding.length];
		System.arraycopy(P, 0, Pcomplete, 0, P.length);
		System.arraycopy(Padding, 0, Pcomplete, P.length, Padding.length);
		byte[] IV = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00 };
		byte[] desKey = new byte[8];
		// der desKey an dieser Stelle muss mit dem desKey in G03b desPaddingOracle.java übereinstimmen
		desKey = "mydeskey".getBytes();  

		byte[] C = new byte[16];
		// verschlüsselung
		// hinweis: Pcomplete wird nicht weiter verwendet, da die des-routine intern das padding
		// anwendet
		// der wert Pcomplete wird nur zur anschauung gezeigt
		C = desCbcPaddingEncrypt(desKey, IV, P);
		// aufteilung von C in C1 und C2
		byte[] C1 = new byte[8];
		C1 = Arrays.copyOfRange(C, 0, 8);
		byte[] C2 = new byte[8];
		C2 = Arrays.copyOfRange(C, 8, 16);

		System.out.println();
		System.out.println("= = = Ausgabe aller Variablen = = =");
		System.out.println("Var P String  [Länge:" + PString.length() + " Byte] :" + PString);
		System.out.println("Var P Hex     [Länge:" + P.length + " Byte] :" + printByteArray(P, 17));
		System.out.println("Var Pcomplete [Länge:" + Pcomplete.length + " Byte] :" + printByteArray(Pcomplete, 35));
		System.out.println("Var IV Hex    [Länge: " + IV.length + " Byte] :" + printByteArray(IV, 9));
		System.out.println("Var C Hex     [Länge:" + C.length + " Byte] :" + printByteArray(C, 17));
		System.out.println("Var C1 Hex    [Länge: " + C1.length + " Byte] :" + printByteArray(C1, 9));
		System.out.println("Var C2 Hex    [Länge: " + C2.length + " Byte] :" + printByteArray(C2, 9));
		System.out.println("= = = Erstellung der Variablen abgeschlossen = = =");
		System.out.println();
		System.out.println("= = = Test des Oracles = = =");
		Boolean oracleSays = desCbcPaddingOracle(IV, C);
		System.out.println(
				"Oracle IV=" + printByteArray(IV, 9) + " C:" + printByteArray(C, 17) + " Ergebnis:" + oracleSays);
		byte[] Cmod = Arrays.copyOf(C, C.length);
		Cmod[15] = (byte) 0x7a;
		oracleSays = desCbcPaddingOracle(IV, Cmod);
		System.out.println(
				"Oracle IV=" + printByteArray(IV, 9) + " C:" + printByteArray(Cmod, 17) + " Ergebnis:" + oracleSays);
		System.out.println("= = = Test des Oracles abgeschlossen = = =");
		System.out.println();
		System.out.println("= = = Kopie der Variablen für desPaddingOracle = = =");
		System.out.println("IV:" + printHexBinary(IV));
		System.out.println("C :" + printHexBinary(C));
		System.out.println("= = = Kopie der Variablen für desPaddingOracle abgeschlossen = = =");
		System.out.println();
		System.out.println("G04a Setup für DES Padding Oracle abgeschlossen");
	}

	public static String printByteArray(byte[] byteData, int numberPerRow) {
		// rückgabe eines strings
		String returnString = "";
		String rawString = printHexBinary(byteData);
		int rawLength = rawString.length();
		int i = 0;
		int j = 1;
		int z = 0;
		for (i = 0; i < rawLength; i++) {
			z++;
			returnString = returnString + rawString.charAt(i);
			if (j == 2) {
				returnString = returnString + " ";
				j = 0;
			}
			j++;
			if (z == (numberPerRow * 2)) {
				returnString = returnString + "\n";
				z = 0;
			}
		}
		return returnString;
	}

	public static byte[] desCbcPaddingEncrypt(byte[] key, byte[] iv, byte[] plaintext) throws Exception {
		Cipher desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, "DES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		desCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
		byte[] encrypt = desCipher.doFinal(plaintext);
		return encrypt;
	}

	@SuppressWarnings("unused")
	public static boolean desCbcPaddingOracle(byte[] iv, byte[] ciphertext) {
		// diese routine gibt das ergebnis des padding oracles zurück
		// ergebnis true = entschlüsselung ist möglich
		// ergebnis false = entschlüsselung ist nicht möglich
		// der schlüssel ist eingebaut wie bei einem entfernten rechner, der auch
		// den schlüssel kennen muss
		byte[] key = "mydeskey".getBytes();
		boolean status = true; // true decryption ohne fehler, false = decryption mit fehler
		Cipher desCipher;
		try {
			desCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "DES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
			desCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			// hinweis das ergebnis decrypt wird nicht weiter benutzt
			// hier ist nur der fehlerteil interessant
			byte[] decrypt = desCipher.doFinal(ciphertext);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			status = false;
		} catch (BadPaddingException e) {
			// e.printStackTrace();
			status = false;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			status = false;
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			status = false;
		}
		return status;
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
