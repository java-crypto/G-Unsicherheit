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
* Der Server basiert auf dem "Webserver in 150 Zeilen" von Anders Moeller 
* The Webserver is based on the "Webserver in 150 lines" from Anders Moeller
* source: http://cs.au.dk/~amoeller/WWW/javaweb/server.html
* 
* Aufruf im Browser / usage in a browser:
* http://localhost:8079/|Base64 dekodierter String>
* falsches Padding / wrong padding:
* http://localhost:8079/AAAAAAAAAAAAAAAAAAAAAAOhCkLI3iLM5pYmWhdB_FM=
* richtiges Padding / correct padding:
* http://localhost:8079/JNB_IdTCPtD6ijpGC13gT5fl1wp9lAeafsGQO4AP0cE=
*/

import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.io.*;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class G05_AesPaddingOracleWebserver {
	public static void main(String[] args) {
		System.out.println("G05 AES CBC Padding Oracle Webserver gestartet");
		int portInt = 8079; // gegebenenfalls individuell ändern
		boolean quietBoolean = true; // auf false ändern gibt statusmeldungen auf die konsole aus

		// webserver starten
		ServerSocket socket = null;
		try {
			socket = new ServerSocket(portInt);
		} catch (IOException e) {
			System.err.println("Kann den Server nicht starten: " + e);
			System.exit(-1);
		}
		// benutzungshinweise des servers
		System.out.println("Der Server antwortet auf Verbindungen an Port: " + portInt);
		System.out.println("Aufruf des Servers: http://localhost:" + portInt + "/ <Base64 dekodiertes Cookie");
		System.out.println("Beispielaufruf    : http://localhost:8079/AAAAAAAAAAAAAAAAAAAAANgYNOrTB3i6R-yyVv9f8XU=");
		System.out.println("Antworten des Servers abhängig vom Ergebnis des AES Padding Oracles:");
		System.out.println("Ungültiges Padding gefunden: HTTP/1.1 500 Invalid Padding");
		System.out.println("Gültiges Padding           : HTTP/1.1 200 OK");

		// schleife für anfragen an den server
		while (true) {
			Socket connection = null;
			try {
				// warten auf die anfrage
				connection = socket.accept();
				BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
				OutputStream out = new BufferedOutputStream(connection.getOutputStream());
				PrintStream pout = new PrintStream(out);

				// nur die erste zeile der anfrage lesen - den rest ignorieren
				String request = in.readLine();
				if (quietBoolean == false) {
					System.out.println("request:" + request);
				}
				if (request == null)
					continue;
				if (quietBoolean == false) {
					log(connection, request);
				}
				while (true) {
					String misc = in.readLine();
					if (misc == null || misc.length() == 0)
						break;
				}

				// die eingabezeile wird analysiert
				if (!request.startsWith("GET") || request.length() < 14
						|| !(request.endsWith("HTTP/1.0") || request.endsWith("HTTP/1.1"))) {
					if (quietBoolean == false) {
						System.out.println("Bad request");
					}
				} else {
					String req = request.substring(4, request.length() - 9).trim();
					if (req.indexOf("..") != -1 || req.indexOf("/.ht") != -1 || req.endsWith("~")) {
						if (quietBoolean == false) {
							System.out.println("Bad request");
						}
					} else {
						String inputString = req.substring(1);
						if (inputString.length() > 12) {
							// die anfrage wird an prepareInput übergeben
							// die rückgabewerte sind 0 [Padding in Ordnung]
							// bzw. 1 [falsches Padding]
							int paddingStatus = prepareInput(inputString);
							if (paddingStatus == 0) {
								if (quietBoolean == false) {
									System.out.println("Der paddingStatus ist 0");
								}
								pout.print("HTTP/1.1 200 OK\r\n" + paddingStatus);
								if (quietBoolean == false) {
									log(connection, "200 OK");
								}
							}
							if (paddingStatus == 1) {
								if (quietBoolean == false) {
									System.out.println("Der paddingStatus ist 1");
								}
								pout.print("HTTP/1.1 500 Invalid Padding\r\n" + paddingStatus);
								if (quietBoolean == false) {
									log(connection, "500 Invalid Padding");
								}
							}
						}
					}
				}
				out.flush();
			} catch (IOException e) {
				System.err.println(e);
			}
			try {
				if (connection != null)
					connection.close();
			} catch (IOException e) {
				System.err.println(e);
			}
		}
	}

	private static void log(Socket connection, String msg) {
		System.err.println(new Date() + " [" + connection.getInetAddress().getHostAddress() + ":" + connection.getPort()
				+ "] " + msg);
	}

	private static int prepareInput(String inputString) {
		// zuerueckverwandlung in ein byte array
		Base64.Decoder decURL = Base64.getUrlDecoder();
		byte[] output = decURL.decode(inputString.getBytes());
		// aufteilung in iv = 16 byte und ct = restliche bytes 16..32..48..
		byte[] iv = null;
		byte[] ct = null;
		iv = Arrays.copyOfRange(output, 0, 16);
		ct = Arrays.copyOfRange(output, 16, output.length);
		int AesCbcPadDecryptStatusBIKint = AesCbcPadDecryptStatusBIK(iv, ct);
		return AesCbcPadDecryptStatusBIKint;
	}

	public static int AesCbcPadDecryptStatusBIK(byte[] initvectorByte, byte[] ciphertextByte) {
		// der server kennt den schlüssel zur entschlüsselung
		// diese routine entschlüsselt nicht, sondern gibt nur eine
		// information zum Padding-Status aus
		byte[] key = "MyAesKey12345678".getBytes();
		int status = 0; // 0=decryption, 1=bad padding, 2=general error
		Cipher AesCipher;
		try {
			AesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			IvParameterSpec ivParameterSpec = new IvParameterSpec(initvectorByte);
			AesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
			byte[] decryptByte = AesCipher.doFinal(ciphertextByte); // decryptByte wird nicht weiter benutzt
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
			status = 2;
		} catch (BadPaddingException e) {
			// e.printStackTrace();
			status = 1;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
			status = 2;
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
			status = 2;
		}
		return status;
	}
}
