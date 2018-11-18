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
* Function: encrypts a file using aes cbc modus with pkcs5 padding
*           saves the initvector in the encrypted file 
*
* Sicherheitshinweis/Security notice
* Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine 
* korrekte Funktion, insbesondere mit Blick auf die Sicherheit ! 
* Prüfen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
* The program routines just show the function but please be aware of the security part - 
* check yourself before using in the real world !
*/

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class G02c_AesCbcPkcs5PaddingRandomFileWithInitvector {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException, FileNotFoundException, IOException {
		System.out.println("G02c Tampering");
		// es werden ein paar variablen benötigt:
		String dateinameReadString = "g02_test.enc"; // aus der datei werden die originalen daten eingelesen
		String dateinameWriteString = "g02_test.enc"; // in diese datei werden die veränderten daten geschrieben

		// der initialisierungsvektor ist exakt 16 zeichen lang
		byte[] initvectorByte = new byte[16];
		// der verschluesselte (encrypted) text kommt in diese variable in form eines
		// byte arrays
		byte[] ciphertextByte = null; // die länge steht noch nicht fest, da sie von der größe des plaintextes abhängt

		String plaintextGuessedString = "Eilauftrag: 1000"; // die geratenen ersten 16 zeichen der mail
		String tamperingtextString    = "Eilauftrag: 9500"; // die geänderten ersten 16 zeichen der mail

		// zuerst testen wir ob die einzulesende datei existiert
		if (FileExistsCheck(dateinameReadString) == false) {
			System.out.println("Die Datei " + dateinameReadString + " existiert nicht. Das Programm wird beendet.");
			System.exit(0);
		};

		// wir starten mit der einleseroutine der verschlüsselten daten
		byte[] initvectorOrgByte = new byte[16]; // zur sicherung des originalwertes
		// der initvectorByte und das ciphertextByte werden aus der datei gelesen
		try (DataInputStream dataIn = new DataInputStream(new FileInputStream(dateinameReadString))) {
			int initvectorSize = dataIn.readInt();
			initvectorOrgByte = new byte[initvectorSize];
			dataIn.read(initvectorOrgByte, 0, initvectorSize);
			int ciphertextSize = dataIn.readInt();
			ciphertextByte = new byte[ciphertextSize];
			dataIn.read(ciphertextByte, 0, ciphertextSize);
		}
		
		// hier erfolgt die veränderung im initvectorByte
		for (int i = 0; i < 16; i++) {
			initvectorByte[i] = (byte) (initvectorOrgByte[i] ^ tamperingtextString.getBytes("UTF-8")[i]
					^ plaintextGuessedString.getBytes("UTF-8")[i]);
		}
			
		// der komplette datensatz wird zurückgeschrieben
		// byte array in eine datei schreiben
		try (DataOutputStream out = new DataOutputStream(new FileOutputStream(dateinameWriteString))) {
			out.writeInt(initvectorByte.length);
			out.write(initvectorByte);
			out.writeInt(ciphertextByte.length);
			out.write(ciphertextByte);
		}

		System.out.println("");
		System.out.println("Verschlüsselte Datei einlesen und nach Tampering als verschlüsselte Datei speichern");
		System.out.println("Dateiname Lesen          :" + dateinameReadString);
		System.out.println("Dateiname Schreiben      :" + dateinameWriteString);
		System.out.println("plaintextGuessedString   :" + plaintextGuessedString);
		System.out.println("tamperingtextString      :" + tamperingtextString);
		System.out.println("initvectorOrgByte (hex)  :" + DatatypeConverter.printHexBinary(initvectorOrgByte));
		System.out.println("initvectorByte File (hex):" + DatatypeConverter.printHexBinary(initvectorByte));
		System.out.println("ciphertextByte (hex)     :" + DatatypeConverter.printHexBinary(ciphertextByte));
	}

	private static boolean FileExistsCheck(String dateinameString) {
		return Files.exists(Paths.get(dateinameString), new LinkOption[] { LinkOption.NOFOLLOW_LINKS });
	}
}
