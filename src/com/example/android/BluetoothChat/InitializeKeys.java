package com.example.android.BluetoothChat;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class InitializeKeys {

	public static void keyCreation(String[] names) {

		File file = new File("/secured-bluetooth-chat/res/raw/keys");
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter(file));
		} catch (IOException ex) {
			System.err.println("Key file not found");
			System.exit(0);
		}

		for (int i = 0; i < names.length; i++) {
			String name = names[i];
			KeyPairGenerator kpg = null;
			try {
				kpg = KeyPairGenerator.getInstance("RSA");
				kpg.initialize(1024);
			} catch (NoSuchAlgorithmException ex) {
				System.exit(0);
			}
			KeyPair kp = kpg.generateKeyPair();
			Key publicKey = kp.getPublic();
			Key privateKey = kp.getPrivate();
			byte[] publicBytes = publicKey.getEncoded();
			byte[] privateBytes = privateKey.getEncoded();

			String sPublicBytes = null;
			String sPrivateBytes = null;
			try {
				sPublicBytes = new String(publicBytes, "UTF-8");
				sPrivateBytes = new String(privateBytes, "UTF-8");

				writer.write(name);
				writer.write("\n");
				writer.write(sPublicBytes);
				writer.write("\n");
				writer.write(sPrivateBytes);
				writer.write("\n");

			} catch (UnsupportedEncodingException ex) {
				System.err.println("Unsupported charset for key generation");
				System.exit(0);
			} catch (Exception ex) {
				System.err.println("I/O error");
				System.exit(0);
			}
		}
	}
}
