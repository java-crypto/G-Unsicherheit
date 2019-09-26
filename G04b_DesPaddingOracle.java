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
* Projekt/Project: G04 DES Padding Orakel / G04 Padding Oracle
* Funktion: zeigt die Unsicherheit durch das Padding Orakel
* Function: shows the unsecurement through the padding oracle
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

//diese routine hält sich eng an die vorlage und jedes byte wird einzeln bearbeitet
//zuerst wird c2 bearbeitet (und damit p2), dann kommt c1 (p1)

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

// basierend auf https://blog.skullsecurity.org/2013/a-padding-oracle-example
// diese routine hält sich eng an die vorlage und jedes byte wird einzeln bearbeitet
// zuerst wird c2 bearbeitet (und damit p2), dann kommt c1 (p1)

public class G04b_DesPaddingOracle {

	public static void main(String[] args) throws Exception {
		System.out.println("G04b DES Padding Oracle");

		/*
		 * The setup As an example, let's assume we're using DES, since it has nice
		 * short block sizes. We'll use the following variables: P = Plaintext (with the
		 * padding added) Pn = The nth block of plaintext N = The number of blocks of
		 * either plaintext or ciphertext (the number is the same) IV = Initialization
		 * vector E() = Encrypt, using a given key (we don't notate the key for reasons
		 * of simplicity) D() = Decrypt, using the same key as E() C = Ciphertext Cn =
		 * The nth block of ciphertext
		 * 
		 * We use the following values for the variables: P =
		 * "Hello World\x05\x05\x05\x05\x05" P1 = "Hello Wo" P2 =
		 * "rld\x05\x05\x05\x05\x05" N = 2 IV = "\x00\x00\x00\x00\x00\x00\x00\x00" E() =
		 * des-cbc with the key "mydeskey" D() = des-cbc with the key "mydeskey" C =
		 * "\x83\xe1\x0d\x51\xe6\xd1\x22\xca\x3f\xaf\x08\x9c\x7a\x92\x4a\x7b" C1 =
		 * "\x83\xe1\x0d\x51\xe6\xd1\x22\xca" C2 = "\x3f\xaf\x08\x9c\x7a\x92\x4a\x7b"
		 * 
		 * For what it's worth, I generated the ciphertext like this: irb(main):001:0>;
		 * require 'openssl' irb(main):002:0>; c =
		 * OpenSSL::Cipher::Cipher.new('des-cbc') irb(main):003:0>; c.encrypt
		 * irb(main):004:0>; c.key = "mydeskey" irb(main):005:0>; c.iv =
		 * "\x00\x00\x00\x00\x00\x00\x00\x00" irb(main):006:0>; data =
		 * c.update("Hello World") + c.final irb(main):007:0>; data.unpack("H*") =>
		 * ["83e10d51e6d122ca3faf089c7a924a7b"]
		 * 
		 */

		// ausgabe der zwischenwerte
		Boolean out1Bool = false; // true = ausgabe, false = keine ausgabe
		// ausgabe der ergebnisse
		Boolean out2Bool = false; // true = ausgabe, false = keine ausgabe

		System.out.println();
		System.out.println("= = = Erstellung bzw. Übernahme der Variablen = = =");
		// übernahme der variablen aus desPaddingOracleSetup
		byte[] IV = decodeHexString("0000000000000000");
		byte[] C  = decodeHexString("83E10D51E6D122CA3FAF089C7A924A7B");

		byte[] C1 = new byte[8];
		C1 = Arrays.copyOfRange(C, 0, 8);
		byte[] C2 = new byte[8];
		C2 = Arrays.copyOfRange(C, 8, 16);

		byte[] D = new byte[16]; // nimmt später die kompletten entschlüsselten daten auf
		// ausgabe
		System.out.println("Var IV     [Länge:" + IV.length + " Byte] :" + printByteArray(IV, 9));
		System.out.println("Var C      [Länge:" + C.length + " Byte]:" + printByteArray(C, 17));
		System.out.println("Var C1     [Länge:" + C1.length + " Byte] :" + printByteArray(C1, 9));
		System.out.println("Var C2     [Länge:" + C2.length + " Byte] :" + printByteArray(C2, 9));
		System.out.println("= = = Erstellung der Variablen abgeschlossen = = =");

		System.out.println();
		System.out.println("= = = Test des desPaddingOracles mit Block C2 = = =");
		// test des oracles mit werten
		boolean desOracle;
		// sollte true ergeben
		desOracle = desCbcPaddingOracle(IV, C);
		System.out.println("desPaddingOracle mit Eingabe:" + printByteArray(C, 17) + ":" + desOracle);
		byte[] Cmodifiziert = new byte[16];
		Cmodifiziert = C;
		Cmodifiziert[15] = (byte) 0x7a;
		desOracle = desCbcPaddingOracle(IV, Cmodifiziert);
		System.out.println("desPaddingOracle mit Eingabe:" + printByteArray(Cmodifiziert, 17) + ":" + desOracle);
		System.out.println("= = = Test des desPaddingOracles abgeschlossen = = =");
		System.out.println();

		System.out.println("= = = Erstellung einer neuen Eingabezeile für das desPaddingOracle = = =");
		// erstellung einer neuen variablen zum brechen des codes
		byte[] Cb1 = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00 };
		System.out.println("Variable Cb1 [Länge:" + Cb1.length + " Byte] :" + printByteArray(Cb1, 9));
		System.out.println("Variable C2  [Länge:" + C2.length + " Byte] :" + printByteArray(C2, 9));
		// verknüpfung der neuen variable mit Block 2 = C2
		byte[] Cb2 = new byte[16];
		System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
		System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
		System.out.println("Variable Cb2 [Länge:" + Cb2.length + " Byte]:" + printByteArray(Cb2, 17));
		// test des oracles
		desOracle = desCbcPaddingOracle(IV, Cb2);
		System.out.println("desPaddingOracle mit Eingabe:" + printByteArray(Cb2, 17) + ":" + desOracle);
		System.out.println("= = = Test der Modifikation am desPaddingOracle abgeschlossen = = =");

		// ======================== Block 1 Anfang =================================

		System.out.println();
		System.out.println(
				"= = = Durchprobieren der Modifikation am desPaddingOracle mit unterschiedlichen Werten = = =");
		// wir verändern nun das letzte byte von cb1, verknüpfen die beiden byte arrays
		System.out.println("Cb1 Schleife   :" + printByteArray(Cb1, 17));
		System.out.println("C2  Original   :" + printByteArray(C2, 17));
		System.out.println("Cb2 Cb1 + C2   :" + printByteArray(Cb2, 17));

		// Cb1 und C2 und testen am desPaddingOracle
		System.out.println("= Byte 08 mit Padding x01 =");

		byte iGesichert = 0; // nimmt das gesuchte i auf, da i nach dem Ende der Schleife nicht mehr
								// verfügbar ist
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(8 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);

			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 08 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von Cb1[8] ist:" + iGesichert + "(byte) Hex:x"
					+ String.format("%02X", iGesichert));
		}
		/*
		 * // ein bischen xor mathematik: P′2[8] = P2[8] ⊕ C1[8] ⊕ C′[8] (re-arrange
		 * using XOR's commutative property): P2[8] = P′2[8] ⊕ C1[8] ⊕ C′[8] P2[8] =
		 * 0x01 ⊕ 0xca ⊕ 0xce P2[8] = 5
		 */
		// folgende formel ergibt sich
		// die zahl hinter (byte) = 1 ist das padding bei einer paddinglänge von 1
		// C1[7] ist das 8. byte unseres original C1 byte arrays
		// Cb1[7] ist das 8. byte des ersten (modifizierten) blocks des Cb1 arrays
		byte P208 = (byte) ((byte) (1) ^ C1[8 - 1] ^ Cb1[8 - 1]);
		if (out2Bool == true) {
			System.out
					.println("Der gesuchte Wert von P2[8] ist:" + P208 + "(byte) Hex:x" + String.format("%02X", P208));
		}
		// mathematik
		byte[] P2t = new byte[8];
		P2t[8 - 1] = P208;

		System.out.println("Treffer für Cb1[8]:x" + String.format("%02X", iGesichert) + " Berechnung P2[8]:x"
				+ String.format("%02X", P208) + " = P'2[8]=:x01" + " ^ C1[8]=:x" + String.format("%02X", (C1[8 - 1]))
				+ " ^ C'[8]=:x" + String.format("%02X", (Cb1[8 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 07 mit Padding x02 =");

		// nun tuen wir so als gäbe es ein zweier-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x02 ⊕ 0x05 ⊕ 0xca C′[8] = 0xcd
		 */
		Cb1[8 - 1] = (byte) ((byte) (2) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(7 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 07 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P207 = (byte) ((byte) (2) ^ C1[7 - 1] ^ Cb1[7 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[7] ist:" + P207 + " Hex:x" + String.format("%02X", P207));
		}
		// mathematik

		P2t[7 - 1] = P207;
		System.out.println("Treffer für Cb1[7]:x" + String.format("%02X", iGesichert) + " Berechnung P2[7]:x"
				+ String.format("%02X", P207) + " = P'2[7]=:x02" + " ^ C1[7]=:x" + String.format("%02X", (C1[7 - 1]))
				+ " ^ C'[7]=:x" + String.format("%02X", (Cb1[7 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 06 mit Padding x03 =");

		// nun tuen wir so als gäbe es ein dreier-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x03 ⊕ 0x05 ⊕ 0xca C′[8] = 0xcc
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x03 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x24
		 */

		Cb1[8 - 1] = (byte) ((byte) (3) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (3) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
		}

		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(6 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 06 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P206 = (byte) ((byte) (3) ^ C1[6 - 1] ^ Cb1[6 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[6] ist:" + P206 + " Hex:x" + String.format("%02X", P206));
		}

		// mathematik
		P2t[6 - 1] = P206;
		System.out.println("Treffer für Cb1[6]:x" + String.format("%02X", iGesichert) + " Berechnung P2[6]:x"
				+ String.format("%02X", P206) + " = P'2[6]=:x03" + " ^ C1[6]=:x" + String.format("%02X", (C1[6 - 1]))
				+ " ^ C'[6]=:x" + String.format("%02X", (Cb1[6 - 1])) + " P2:" + printByteArray(P2t, 17));
		System.out.println("= Byte 05 mit Padding x04 =");

		// nun tuen wir so als gäbe es ein vierer-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x04 ⊕ 0x05 ⊕ 0xca C′[8] = 0xcb
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x04 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x23
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x04 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd0
		 */

		Cb1[8 - 1] = (byte) ((byte) (4) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (4) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (4) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
		}

		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(5 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 05 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P205 = (byte) ((byte) (4) ^ C1[5 - 1] ^ Cb1[5 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[5] ist:" + P205 + " Hex:x" + String.format("%02X", P205));
		}

		// mathematik
		P2t[5 - 1] = P205;
		System.out.println("Treffer für Cb1[5]:x" + String.format("%02X", iGesichert) + " Berechnung P2[5]:x"
				+ String.format("%02X", P205) + " = P'2[5]=:x04" + " ^ C1[5]=:x" + String.format("%02X", (C1[5 - 1]))
				+ " ^ C'[5]=:x" + String.format("%02X", (Cb1[5 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 04 mit Padding x05 =");

		// nun tuen wir so als gäbe es ein fünfer-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x05 ⊕ 0x05 ⊕ 0xca C′[8] = 0xca
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x05 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x22
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x05 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd1
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x05 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xe6
		 */

		Cb1[8 - 1] = (byte) ((byte) (5) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (5) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (5) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (5) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(4 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 04 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P204 = (byte) ((byte) (5) ^ C1[4 - 1] ^ Cb1[4 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[4] ist:" + P204 + " Hex:x" + String.format("%02X", P204));
		}
		// mathematik
		P2t[4 - 1] = P204;
		System.out.println("Treffer für Cb1[4]:x" + String.format("%02X", iGesichert) + " Berechnung P2[4]:x"
				+ String.format("%02X", P204) + " = P'2[4]=:x05" + " ^ C1[4]=:x" + String.format("%02X", (C1[4 - 1]))
				+ " ^ C'[4]=:x" + String.format("%02X", (Cb1[4 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 03 mit Padding x06 =");

		// nun tuen wir so als gäbe es ein sechser-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x06 ⊕ 0x05 ⊕ 0xca C′[8] = 0xc9
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x06 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x21
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x06 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd2
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x06 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xe5
		 * 
		 * C′[4] = P′2[4] ⊕ P2[4] ⊕ C1[4] C′[4] = 0x06 ⊕ 0x05 ⊕ 0x51 C′[4] = 0x52
		 */

		Cb1[8 - 1] = (byte) ((byte) (6) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (6) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (6) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (6) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		Cb1[4 - 1] = (byte) ((byte) (6) ^ (byte) (P204) ^ (byte) (C1[4 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + Cb1[4 - 1] + " Hex:x" + String.format("%02X", Cb1[4 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(3 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 03 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[3-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P203 = (byte) ((byte) (6) ^ C1[3 - 1] ^ Cb1[3 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[3] ist:" + P203 + " Hex:x" + String.format("%02X", P203));
		}

		// mathematik
		P2t[3 - 1] = P203;
		System.out.println("Treffer für Cb1[3]:x" + String.format("%02X", iGesichert) + " Berechnung P2[3]:x"
				+ String.format("%02X", P203) + " = P'2[3]=:x06" + " ^ C1[3]=:x" + String.format("%02X", (C1[3 - 1]))
				+ " ^ C'[3]=:x" + String.format("%02X", (Cb1[3 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 02 mit Padding x07 =");

		// nun tuen wir so als gäbe es ein siebener-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x07 ⊕ 0x05 ⊕ 0xca C′[8] = 0xc9
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x07 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x21
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x07 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd2
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x07 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xe5
		 * 
		 * C′[4] = P′2[4] ⊕ P2[4] ⊕ C1[4] C′[4] = 0x07 ⊕ 0x05 ⊕ 0x51 C′[4] = 0x52
		 * 
		 * C′[3] = P′2[3] ⊕ P2[3] ⊕ C1[3] C′[3] = 0x07 ⊕ 0x64 ⊕ 0x0d C′[3] = 0x52
		 */

		Cb1[8 - 1] = (byte) ((byte) (7) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (7) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (7) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (7) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		Cb1[4 - 1] = (byte) ((byte) (7) ^ (byte) (P204) ^ (byte) (C1[4 - 1]));
		Cb1[3 - 1] = (byte) ((byte) (7) ^ (byte) (P203) ^ (byte) (C1[3 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + Cb1[4 - 1] + " Hex:x" + String.format("%02X", Cb1[4 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[3-1] ist:" + Cb1[3 - 1] + " Hex:x" + String.format("%02X", Cb1[3 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(2 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 02 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[2-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P202 = (byte) ((byte) (7) ^ C1[2 - 1] ^ Cb1[2 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[2] ist:" + P202 + " Hex:x" + String.format("%02X", P202));
		}

		// mathematik
		P2t[2 - 1] = P202;
		System.out.println("Treffer für Cb1[2]:x" + String.format("%02X", iGesichert) + " Berechnung P2[2]:x"
				+ String.format("%02X", P202) + " = P'2[2]=:x07" + " ^ C1[2]=:x" + String.format("%02X", (C1[2 - 1]))
				+ " ^ C'[2]=:x" + String.format("%02X", (Cb1[2 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 01 mit Padding x08 =");

		// nun tuen wir so als gäbe es ein achterer-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x08 ⊕ 0x05 ⊕ 0xca C′[8] = 0xc7
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x08 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x2f
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x08 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xdc
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x08 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xeb
		 * 
		 * C′[4] = P′2[4] ⊕ P2[4] ⊕ C1[4] C′[4] = 0x08 ⊕ 0x05 ⊕ 0x51 C′[4] = 0x5c
		 * 
		 * C′[3] = P′2[3] ⊕ P2[3] ⊕ C1[3] C′[3] = 0x08 ⊕ 0x64 ⊕ 0x0d C′[3] = 0x61
		 * 
		 * C′[2] = P′2[2] ⊕ P2[2] ⊕ C1[2] C′[2] = 0x08 ⊕ 0x6c ⊕ 0xe1 C′[2] = 0x85
		 */

		Cb1[8 - 1] = (byte) ((byte) (8) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (8) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (8) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (8) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		Cb1[4 - 1] = (byte) ((byte) (8) ^ (byte) (P204) ^ (byte) (C1[4 - 1]));
		Cb1[3 - 1] = (byte) ((byte) (8) ^ (byte) (P203) ^ (byte) (C1[3 - 1]));
		Cb1[2 - 1] = (byte) ((byte) (8) ^ (byte) (P202) ^ (byte) (C1[2 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + Cb1[4 - 1] + " Hex:x" + String.format("%02X", Cb1[4 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[3-1] ist:" + Cb1[3 - 1] + " Hex:x" + String.format("%02X", Cb1[3 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[2-1] ist:" + Cb1[2 - 1] + " Hex:x" + String.format("%02X", Cb1[2 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(1 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 01 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[1-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		byte P201 = (byte) ((byte) (8) ^ C1[1 - 1] ^ Cb1[1 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[1] ist:" + P201 + " Hex:x" + String.format("%02X", P201));
		}

		// mathematik
		P2t[1 - 1] = P201;
		System.out.println("Treffer für Cb1[1]:x" + String.format("%02X", iGesichert) + " Berechnung P2[1]:x"
				+ String.format("%02X", P201) + " = P'2[1]=:x08" + " ^ C1[1]=:x" + String.format("%02X", (C1[1 - 1]))
				+ " ^ C'[1]=:x" + String.format("%02X", (Cb1[1 - 1])) + " P2:" + printByteArray(P2t, 17));

		// ergebnis
		byte[] decrypted2Byte = { P201, P202, P203, P204, P205, P206, P207, P208 };
		String decrypted2String = aBtS(decrypted2Byte);
		System.out.println("Umwandlung von P2t:" + printByteArray(P2t, 17) + "in einen String:" + decrypted2String);

		System.out.println();
		System.out.println(
				"= = = Durchprobieren der Modifikation am desOracle mit unterschiedlichen Werten abgeschlossen = = =");

		// ======================== Block 1 Ende =================================

		System.out.println();
		System.out.println("= = = Test des desOracles mit Block C1 = = =");
		// diese modifikation erzeugt den wert des ersten blockes
		System.arraycopy(C1, 0, C2, 0, C1.length);
		System.arraycopy(IV, 0, C1, 0, IV.length);

		// verknüpfung der neuen variable mit Block 2 = C2
		Cb1 = new byte[] { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00 };
		Cb2 = new byte[16];
		System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
		System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
		System.out.println("Var Cb2    [Länge:" + Cb2.length + " Byte]:" + printHexBinary(Cb2));
		// test des oracles
		desOracle = desCbcPaddingOracle(IV, Cb2);
		System.out.println("desOracle mit Eingabe     :" + printHexBinary(Cb2) + ":" + desOracle);

		System.out.println("= = = Test der Modifikation am desOracle abgeschlossen = = =");

		// Block 2
		System.out.println();
		System.out.println(
				"= = = Durchprobieren der Modifikation am desPaddingOracle mit unterschiedlichen Werten = = =");
		// wir verändern nun das letzte byte von cb1, verknüpfen die beiden byte arrays
		System.out.println("Cb1 Schleife   :" + printByteArray(Cb1, 17));
		System.out.println("C2  Original   :" + printByteArray(C2, 17));
		System.out.println("Cb2 Cb1 + C2   :" + printByteArray(Cb2, 17));

		// Cb1 und C2 und testen am desPaddingOracle
		System.out.println("= Byte 08 mit Padding x01 =");

		iGesichert = 0; // nimmt das gesuchte i auf, da i nach dem Ende der Schleife nicht mehr
						// verfügbar ist
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(8 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);

			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 08 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von Cb1[8] ist:" + iGesichert + "(byte) Hex:x"
					+ String.format("%02X", iGesichert));
		}
		/*
		 * // ein bischen xor mathematik: P′2[8] = P2[8] ⊕ C1[8] ⊕ C′[8] (re-arrange
		 * using XOR's commutative property): P2[8] = P′2[8] ⊕ C1[8] ⊕ C′[8] P2[8] =
		 * 0x01 ⊕ 0xca ⊕ 0xce P2[8] = 5
		 */
		// folgende formel ergibt sich
		// die zahl hinter (byte) = 1 ist das padding bei einer paddinglänge von 1
		// C1[7] ist das 8. byte unseres original C1 byte arrays
		// Cb1[7] ist das 8. byte des ersten (modifizierten) blocks des Cb1 arrays
		P208 = (byte) ((byte) (1) ^ C1[8 - 1] ^ Cb1[8 - 1]);
		if (out2Bool == true) {
			System.out
					.println("Der gesuchte Wert von P2[8] ist:" + P208 + "(byte) Hex:x" + String.format("%02X", P208));
		}
		// mathematik
		P2t = new byte[8];
		P2t[8 - 1] = P208;

		System.out.println("Treffer für Cb1[8]:x" + String.format("%02X", iGesichert) + " Berechnung P2[8]:x"
				+ String.format("%02X", P208) + " = P'2[8]=:x01" + " ^ C1[8]=:x" + String.format("%02X", (C1[8 - 1]))
				+ " ^ C'[8]=:x" + String.format("%02X", (Cb1[8 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 07 mit Padding x02 =");

		// nun tuen wir so als gäbe es ein zweier-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x02 ⊕ 0x05 ⊕ 0xca C′[8] = 0xcd
		 */
		Cb1[8 - 1] = (byte) ((byte) (2) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(7 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 07 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P207 = (byte) ((byte) (2) ^ C1[7 - 1] ^ Cb1[7 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[7] ist:" + P207 + " Hex:x" + String.format("%02X", P207));
		}
		// mathematik

		P2t[7 - 1] = P207;
		System.out.println("Treffer für Cb1[7]:x" + String.format("%02X", iGesichert) + " Berechnung P2[7]:x"
				+ String.format("%02X", P207) + " = P'2[7]=:x02" + " ^ C1[7]=:x" + String.format("%02X", (C1[7 - 1]))
				+ " ^ C'[7]=:x" + String.format("%02X", (Cb1[7 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 06 mit Padding x03 =");

		// nun tuen wir so als gäbe es ein dreier-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x03 ⊕ 0x05 ⊕ 0xca C′[8] = 0xcc
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x03 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x24
		 */

		Cb1[8 - 1] = (byte) ((byte) (3) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (3) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
		}

		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(6 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 06 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P206 = (byte) ((byte) (3) ^ C1[6 - 1] ^ Cb1[6 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[6] ist:" + P206 + " Hex:x" + String.format("%02X", P206));
		}

		// mathematik
		P2t[6 - 1] = P206;
		System.out.println("Treffer für Cb1[6]:x" + String.format("%02X", iGesichert) + " Berechnung P2[6]:x"
				+ String.format("%02X", P206) + " = P'2[6]=:x03" + " ^ C1[6]=:x" + String.format("%02X", (C1[6 - 1]))
				+ " ^ C'[6]=:x" + String.format("%02X", (Cb1[6 - 1])) + " P2:" + printByteArray(P2t, 17));
		System.out.println("= Byte 05 mit Padding x04 =");

		// nun tuen wir so als gäbe es ein vierer-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x04 ⊕ 0x05 ⊕ 0xca C′[8] = 0xcb
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x04 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x23
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x04 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd0
		 */

		Cb1[8 - 1] = (byte) ((byte) (4) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (4) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (4) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
		}

		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(5 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 05 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P205 = (byte) ((byte) (4) ^ C1[5 - 1] ^ Cb1[5 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[5] ist:" + P205 + " Hex:x" + String.format("%02X", P205));
		}

		// mathematik
		P2t[5 - 1] = P205;
		System.out.println("Treffer für Cb1[5]:x" + String.format("%02X", iGesichert) + " Berechnung P2[5]:x"
				+ String.format("%02X", P205) + " = P'2[5]=:x04" + " ^ C1[5]=:x" + String.format("%02X", (C1[5 - 1]))
				+ " ^ C'[5]=:x" + String.format("%02X", (Cb1[5 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 04 mit Padding x05 =");

		// nun tuen wir so als gäbe es ein fünfer-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x05 ⊕ 0x05 ⊕ 0xca C′[8] = 0xca
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x05 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x22
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x05 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd1
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x05 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xe6
		 */

		Cb1[8 - 1] = (byte) ((byte) (5) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (5) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (5) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (5) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(4 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 04 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P204 = (byte) ((byte) (5) ^ C1[4 - 1] ^ Cb1[4 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[4] ist:" + P204 + " Hex:x" + String.format("%02X", P204));
		}
		// mathematik
		P2t[4 - 1] = P204;
		System.out.println("Treffer für Cb1[4]:x" + String.format("%02X", iGesichert) + " Berechnung P2[4]:x"
				+ String.format("%02X", P204) + " = P'2[4]=:x05" + " ^ C1[4]=:x" + String.format("%02X", (C1[4 - 1]))
				+ " ^ C'[4]=:x" + String.format("%02X", (Cb1[4 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 03 mit Padding x06 =");

		// nun tuen wir so als gäbe es ein sechser-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x06 ⊕ 0x05 ⊕ 0xca C′[8] = 0xc9
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x06 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x21
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x06 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd2
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x06 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xe5
		 * 
		 * C′[4] = P′2[4] ⊕ P2[4] ⊕ C1[4] C′[4] = 0x06 ⊕ 0x05 ⊕ 0x51 C′[4] = 0x52
		 */

		Cb1[8 - 1] = (byte) ((byte) (6) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (6) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (6) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (6) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		Cb1[4 - 1] = (byte) ((byte) (6) ^ (byte) (P204) ^ (byte) (C1[4 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + Cb1[4 - 1] + " Hex:x" + String.format("%02X", Cb1[4 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(3 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 03 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[3-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P203 = (byte) ((byte) (6) ^ C1[3 - 1] ^ Cb1[3 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[3] ist:" + P203 + " Hex:x" + String.format("%02X", P203));
		}

		// mathematik
		P2t[3 - 1] = P203;
		System.out.println("Treffer für Cb1[3]:x" + String.format("%02X", iGesichert) + " Berechnung P2[3]:x"
				+ String.format("%02X", P203) + " = P'2[3]=:x06" + " ^ C1[3]=:x" + String.format("%02X", (C1[3 - 1]))
				+ " ^ C'[3]=:x" + String.format("%02X", (Cb1[3 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 02 mit Padding x07 =");

		// nun tuen wir so als gäbe es ein siebener-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x07 ⊕ 0x05 ⊕ 0xca C′[8] = 0xc9
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x07 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x21
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x07 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xd2
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x07 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xe5
		 * 
		 * C′[4] = P′2[4] ⊕ P2[4] ⊕ C1[4] C′[4] = 0x07 ⊕ 0x05 ⊕ 0x51 C′[4] = 0x52
		 * 
		 * C′[3] = P′2[3] ⊕ P2[3] ⊕ C1[3] C′[3] = 0x07 ⊕ 0x64 ⊕ 0x0d C′[3] = 0x52
		 */

		Cb1[8 - 1] = (byte) ((byte) (7) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (7) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (7) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (7) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		Cb1[4 - 1] = (byte) ((byte) (7) ^ (byte) (P204) ^ (byte) (C1[4 - 1]));
		Cb1[3 - 1] = (byte) ((byte) (7) ^ (byte) (P203) ^ (byte) (C1[3 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + Cb1[4 - 1] + " Hex:x" + String.format("%02X", Cb1[4 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[3-1] ist:" + Cb1[3 - 1] + " Hex:x" + String.format("%02X", Cb1[3 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(2 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 02 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[2-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P202 = (byte) ((byte) (7) ^ C1[2 - 1] ^ Cb1[2 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[2] ist:" + P202 + " Hex:x" + String.format("%02X", P202));
		}

		// mathematik
		P2t[2 - 1] = P202;
		System.out.println("Treffer für Cb1[2]:x" + String.format("%02X", iGesichert) + " Berechnung P2[2]:x"
				+ String.format("%02X", P202) + " = P'2[2]=:x07" + " ^ C1[2]=:x" + String.format("%02X", (C1[2 - 1]))
				+ " ^ C'[2]=:x" + String.format("%02X", (Cb1[2 - 1])) + " P2:" + printByteArray(P2t, 17));

		System.out.println("= Byte 01 mit Padding x08 =");

		// nun tuen wir so als gäbe es ein achter-padding
		/*
		 * C′[8] = P′2[8] ⊕ P2[8] ⊕ C1[8] C′[8] = 0x08 ⊕ 0x05 ⊕ 0xca C′[8] = 0xc7
		 * 
		 * C′[7] = P′2[7] ⊕ P2[7] ⊕ C1[7] C′[7] = 0x08 ⊕ 0x05 ⊕ 0x22 C′[7] = 0x2f
		 * 
		 * C′[6] = P′2[6] ⊕ P2[6] ⊕ C1[6] C′[6] = 0x08 ⊕ 0x05 ⊕ 0xd1 C′[6] = 0xdc
		 * 
		 * C′[5] = P′2[5] ⊕ P2[5] ⊕ C1[5] C′[5] = 0x08 ⊕ 0x05 ⊕ 0xe6 C′[5] = 0xeb
		 * 
		 * C′[4] = P′2[4] ⊕ P2[4] ⊕ C1[4] C′[4] = 0x08 ⊕ 0x05 ⊕ 0x51 C′[4] = 0x5c
		 * 
		 * C′[3] = P′2[3] ⊕ P2[3] ⊕ C1[3] C′[3] = 0x08 ⊕ 0x64 ⊕ 0x0d C′[3] = 0x61
		 * 
		 * C′[2] = P′2[2] ⊕ P2[2] ⊕ C1[2] C′[2] = 0x08 ⊕ 0x6c ⊕ 0xe1 C′[2] = 0x85
		 */

		Cb1[8 - 1] = (byte) ((byte) (8) ^ (byte) (P208) ^ (byte) (C1[8 - 1]));
		Cb1[7 - 1] = (byte) ((byte) (8) ^ (byte) (P207) ^ (byte) (C1[7 - 1]));
		Cb1[6 - 1] = (byte) ((byte) (8) ^ (byte) (P206) ^ (byte) (C1[6 - 1]));
		Cb1[5 - 1] = (byte) ((byte) (8) ^ (byte) (P205) ^ (byte) (C1[5 - 1]));
		Cb1[4 - 1] = (byte) ((byte) (8) ^ (byte) (P204) ^ (byte) (C1[4 - 1]));
		Cb1[3 - 1] = (byte) ((byte) (8) ^ (byte) (P203) ^ (byte) (C1[3 - 1]));
		Cb1[2 - 1] = (byte) ((byte) (8) ^ (byte) (P202) ^ (byte) (C1[2 - 1]));
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[8-1] ist:" + Cb1[8 - 1] + " Hex:x" + String.format("%02X", Cb1[8 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[7-1] ist:" + Cb1[7 - 1] + " Hex:x" + String.format("%02X", Cb1[7 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[6-1] ist:" + Cb1[6 - 1] + " Hex:x" + String.format("%02X", Cb1[6 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[5-1] ist:" + Cb1[5 - 1] + " Hex:x" + String.format("%02X", Cb1[5 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[4-1] ist:" + Cb1[4 - 1] + " Hex:x" + String.format("%02X", Cb1[4 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[3-1] ist:" + Cb1[3 - 1] + " Hex:x" + String.format("%02X", Cb1[3 - 1]));
			System.out.println(
					"Der gesuchte Wert von Cb1[2-1] ist:" + Cb1[2 - 1] + " Hex:x" + String.format("%02X", Cb1[2 - 1]));
		}
		iGesichert = 0;
		// diese schleife probiert alle 256 bytes aus
		for (int i = 0; i < 256; i++) {
			Cb1[(1 - 1)] = (byte) i;
			System.arraycopy(Cb1, 0, Cb2, 0, Cb1.length);
			System.arraycopy(C2, 0, Cb2, Cb1.length, C2.length);
			desOracle = desCbcPaddingOracle(IV, Cb2);
			if (out1Bool == true) {
				System.out.println("Cb2 Byte 01 x01:" + printByteArray(Cb2, 17) + "Oracle:" + desOracle);
			}
			if (desOracle == true) {
				iGesichert = (byte) i;
				break;
			}
		}
		if (out2Bool == true) {
			System.out.println(
					"Der gesuchte Wert von Cb1[1-1] ist:" + iGesichert + " Hex:x" + String.format("%02X", iGesichert));
		}
		P201 = (byte) ((byte) (8) ^ C1[1 - 1] ^ Cb1[1 - 1]);
		if (out2Bool == true) {
			System.out.println("Der gesuchte Wert von P2[1] ist:" + P201 + " Hex:x" + String.format("%02X", P201));
		}

		// mathematik
		P2t[1 - 1] = P201;
		System.out.println("Treffer für Cb1[1]:x" + String.format("%02X", iGesichert) + " Berechnung P2[1]:x"
				+ String.format("%02X", P201) + " = P'2[1]=:x08" + " ^ C1[1]=:x" + String.format("%02X", (C1[1 - 1]))
				+ " ^ C'[1]=:x" + String.format("%02X", (Cb1[1 - 1])) + " P2:" + printByteArray(P2t, 17));

		//ergebnis

		byte[] decrypted1Byte = { P201, P202, P203, P204, P205, P206, P207, P208 };
		String decrypted1String = aBtS(decrypted1Byte);
		System.out.println("Umwandlung von P2t:" + printByteArray(P2t, 17) + "in einen String:" + decrypted1String);

		System.out.println(
				"= = = Durchprobieren der Modifikation am desOracle mit unterschiedlichen Werten abgeschlossen = = =");
		
		System.out.println("= = = Entschlüsselung des gesamten Strings = = =");
		// sicherung der daten in D
		System.arraycopy(decrypted1Byte, 0, D, 0, decrypted1Byte.length);
		System.arraycopy(decrypted2Byte, 0, D, decrypted1Byte.length, decrypted2Byte.length);
		String decryptedString = aBtS(D);
		System.out.println("Entschlüsselter String:" + decryptedString);
		System.out.println("= = = Entschlüsselung des gesamten Strings abgeschlossen = = =");

		System.out.println("G04b DES Padding Oracle beendet");
	}

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
			@SuppressWarnings("unused")
			byte[] decrypt = desCipher.doFinal(ciphertext);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			status = false;
		} catch (BadPaddingException e) {
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

	// public static String asciiBytesToString( byte[] bytes )
	public static String aBtS(byte[] bytes) {
		if ((bytes == null) || (bytes.length == 0)) {
			return "";
		}
		char[] result = new char[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			result[i] = (char) bytes[i];
		}
		return new String(result);
	}

	public static byte[] decodeHexString(String hexString) {
		if (hexString.length() % 2 == 1) {
			throw new IllegalArgumentException("Invalid hexadecimal String supplied.");
		}
		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < hexString.length(); i += 2) {
			bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
		}
		return bytes;
	}

	public static byte hexToByte(String hexString) {
		int firstDigit = toDigit(hexString.charAt(0));
		int secondDigit = toDigit(hexString.charAt(1));
		return (byte) ((firstDigit << 4) + secondDigit);
	}

	private static int toDigit(char hexChar) {
		int digit = Character.digit(hexChar, 16);
		if (digit == -1) {
			throw new IllegalArgumentException("Invalid Hexadecimal Character: " + hexChar);
		}
		return digit;
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
