import java.awt.EventQueue;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.filechooser.FileNameExtensionFilter;

public class CryptMenu {

	private JFrame frmdecryptoApp;

	// default key size
	private static int textAlgorithmKeySize = 128;

	private static int keyAlgorithmKeySize = 1024;

	private static String textAlgorithm = "AES";

	private static String hashFunction = "SHA-1";

	private static int hashFunctionDigestSize = 128;

	private static String cipherMode = "ECB";

	private Map<String, String> entryData = new LinkedHashMap<>();

	private static SecretKey keyAESTest = null;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					CryptMenu window = new CryptMenu();
					window.frmdecryptoApp.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public CryptMenu() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {

		frmdecryptoApp = new JFrame();
		frmdecryptoApp.setTitle("(De)Crypto App");
		frmdecryptoApp.setBounds(100, 100, 651, 304);
		frmdecryptoApp.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frmdecryptoApp.getContentPane().setLayout(null);
		DigitalEnvelope digitalEnvelope = new DigitalEnvelope();
		KeyGenerator keyGenerator;
		try {
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(textAlgorithmKeySize);
			keyAESTest = keyGenerator.generateKey();
		} catch (NoSuchAlgorithmException e3) {
			e3.printStackTrace();
		}

		JPanel panel = new JPanel();
		panel.setBounds(0, 0, 669, 123);
		frmdecryptoApp.getContentPane().add(panel);
		panel.setLayout(null);

		JLabel lblChooseAlgorithm = new JLabel("Choose algorithm for text encryption:");
		lblChooseAlgorithm.setBounds(10, 36, 246, 14);
		panel.add(lblChooseAlgorithm);

		final JComboBox comboBox_1 = new JComboBox();
		comboBox_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String algorithm_keysize = comboBox_1.getSelectedItem().toString();
				textAlgorithmKeySize = Integer.parseInt(algorithm_keysize.split(" ")[1]);
				textAlgorithm = algorithm_keysize.split(" ")[0];
			}
		});
		comboBox_1.setModel(
				new DefaultComboBoxModel(new String[] { "AES 128", "AES 192", "AES 256", "3DES 112", "3DES 168" }));
		comboBox_1.setBounds(232, 33, 72, 20);
		panel.add(comboBox_1);

		JLabel lblNewLabel_1 = new JLabel("Block Cipher Mode of Operation : ");
		lblNewLabel_1.setBounds(342, 36, 226, 14);
		panel.add(lblNewLabel_1);

		final JComboBox comboBox_2 = new JComboBox();
		comboBox_2.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				cipherMode = comboBox_2.getSelectedItem().toString();
			}
		});
		comboBox_2.setModel(new DefaultComboBoxModel(new String[] { "ECB", "CTR", "CBC" }));
		comboBox_2.setBounds(565, 33, 56, 20);
		panel.add(comboBox_2);

		JLabel lblChooseHashFunction = new JLabel("Choose hash function : ");
		lblChooseHashFunction.setBounds(342, 77, 197, 14);
		panel.add(lblChooseHashFunction);

		final JComboBox comboBox_3 = new JComboBox();
		comboBox_3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String hash_digestSize = comboBox_3.getSelectedItem().toString();
				if (!hash_digestSize.equals("SHA1-128")) {
					hashFunction = hash_digestSize.split("-")[0];
					hashFunctionDigestSize = Integer.parseInt(hash_digestSize.split("-")[1]);
				}
			}
		});
		comboBox_3.setModel(new DefaultComboBoxModel(new String[] { "SHA1-128", "SHA-256", "SHA-384", "SHA-512" }));
		comboBox_3.setBounds(498, 74, 123, 20);
		panel.add(comboBox_3);

		JComboBox comboBox_4 = new JComboBox();
		comboBox_4.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				String item = comboBox_4.getSelectedItem().toString();
				keyAlgorithmKeySize = Integer.parseInt(item.split(" ")[1]);
			}
		});
		comboBox_4.setModel(new DefaultComboBoxModel(new String[] { "RSA 1024", "RSA 2048" }));
		comboBox_4.setBounds(232, 74, 96, 20);
		panel.add(comboBox_4);

		JLabel lblChooseAlgorithmFor = new JLabel("Choose algorithm for key encryption:");
		lblChooseAlgorithmFor.setBounds(10, 77, 246, 14);
		panel.add(lblChooseAlgorithmFor);

		JLabel lblOptions = new JLabel("OPTIONS");
		lblOptions.setFont(new Font("Segoe Print", Font.BOLD, 16));
		lblOptions.setBounds(285, 11, 155, 14);
		panel.add(lblOptions);

		JButton btnSignature = new JButton("Create digital signature");
		btnSignature.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				int dialogButton = JOptionPane.YES_NO_OPTION;
				int dialogResult = JOptionPane.showConfirmDialog(null,
						"Are you sure you want to create digital signature?", "Confirmation", dialogButton);
				if (dialogResult == JOptionPane.YES_OPTION) {
					String text = entryData.get("text");
					String secretKey = entryData.get("secretKey");
					byte[] decryptedHash = null;
					if (text == null) {
						JOptionPane.showMessageDialog(frmdecryptoApp, "No entry data initialized!");
					} else {
						// digital signature here...
						DigitalSignature digitalSignature = new DigitalSignature();
						KeyPair keyPair = null;
						byte[] encryptedHash = null;
						// this is C1
						String P = text;
						byte[] H_P = null;
						byte[] H_PP = null;
						try {
							H_P = hashText(P);
							P = P + "aha";
							H_PP = hashText(P);
							int keySize = keyAlgorithmKeySize;
							KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
							keyPairGenerator.initialize(keySize);
							keyPair = keyPairGenerator.genKeyPair();
							// this is C2
							// for SHA-512 it says data should not be longer than 117 bytes...
							System.out.println("Original hash = " + new String(H_PP));
							encryptedHash = encryptRSAforHash(H_P, keyPair.getPrivate());
							System.out.println("Encrypted hash = " + new String(encryptedHash));
							decryptedHash = decryptRSAForHash(encryptedHash, keyPair.getPublic());
							System.out.println("Decrypted hash = " + new String(decryptedHash));
							if (new String(H_PP).equals(new String(decryptedHash))) {
								System.out.println(
										"Hash is identycal to the calculated one! It really came from my friend!");
							}else {
								System.out.println(":o. It didn't come from a friend!");
							}
						} catch (Exception e) {
							e.printStackTrace();
						}

						digitalSignature.setClearText(P);
						digitalSignature.setEncryptedHash(encryptedHash);
						System.out.println(digitalSignature);
						System.out.println("------------------------------------------------");
					}
				}
			}
		});
		btnSignature.setBounds(216, 232, 192, 23);
		frmdecryptoApp.getContentPane().add(btnSignature);

		JButton btnEnvelope = new JButton("Create digital envelope");
		btnEnvelope.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				int dialogButton = JOptionPane.YES_NO_OPTION;
				int dialogResult = JOptionPane.showConfirmDialog(null,
						"Are you sure you want to create digital envelope?", "Confirmation", dialogButton);
				if (dialogResult == JOptionPane.YES_OPTION) {

					digitalEnvelope.setEncryptedKey(null);
					digitalEnvelope.setEncryptedText(null);
					String text = entryData.get("text");
					byte[] encryptedByteText = null;
					String encryptedText = null;
					String decryptedText = null;
					byte[] encryptedKey = null;
					String decryptedKey = null;
					String secretKey = entryData.get("secretKey");
					KeyPair keyPair = null;
					try {
						int keySize = keyAlgorithmKeySize;
						KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
						keyPairGenerator.initialize(keySize);
						// generates new key pair(private/public key) every time it's called
						keyPair = keyPairGenerator.genKeyPair();
					} catch (NoSuchAlgorithmException e) {
						e.printStackTrace();
					}
					if (text == null) {
						JOptionPane.showMessageDialog(frmdecryptoApp, "No entry data initialized!");
					} else {
						// digital envelope here...
						System.out.println("Original text=" + text);
						if (textAlgorithm.equals("AES")) {
							encryptedText = encryptAES(text, secretKey);
							System.out.println("Encrypted text=" + encryptedText);
							try {
								System.out.println("Original secret key K =" + new String(keyAESTest.getEncoded()));
								encryptedKey = encryptRSA(new String(keyAESTest.getEncoded()), keyPair.getPublic());
								System.out.println("Encrypted secret key K=" + new String(encryptedKey));
								decryptedKey = new String(decryptRSA(keyPair.getPrivate(), encryptedKey));
								System.out.println("Decrypted secret key K=" + decryptedKey);
								System.out.println("Decrypted text=" + decryptAES(encryptedText, decryptedKey));
							} catch (Exception e1) {
								e1.printStackTrace();
							}
						} else if (textAlgorithm.equals("3DES")) {
							try {
								encryptedByteText = encrypt3DES(text, secretKey);
								encryptedText = new String(encryptedByteText);
								System.out.println("Encrypted text=" + encryptedText);
								System.out.println("Original secret key K =" + secretKey);
								encryptedKey = encryptRSA(secretKey, keyPair.getPublic());
								System.out.println("Encrypted secret key K=" + new String(encryptedKey));
								decryptedKey = new String(decryptRSA(keyPair.getPrivate(), encryptedKey));
								System.out.println("Decrypted secret key K=" + decryptedKey);
								decryptedText = decrypt3DES(encryptedByteText, decryptedKey);
								System.out.println("Decrypted text=" + decryptedText);
							} catch (Exception e) {
								e.printStackTrace();
							}

						}
						digitalEnvelope.setEncryptedKey(encryptedKey);
						digitalEnvelope.setEncryptedText(encryptedText);
						System.out.println(digitalEnvelope.toString());
						System.out.println("------------------------------------------------");
					}
				}
			}

		});
		btnEnvelope.setBounds(0, 232, 192, 23);
		frmdecryptoApp.getContentPane().add(btnEnvelope);

		JButton btnCreateDigitalSeal = new JButton("Create digital seal");
		btnCreateDigitalSeal.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				int dialogButton = JOptionPane.YES_NO_OPTION;
				int dialogResult = JOptionPane.showConfirmDialog(null, "Are you sure you want to create digital seal?",
						"Confirmation", dialogButton);
				if (dialogResult == JOptionPane.YES_OPTION) {
					String text = entryData.get("text");
					String secretKey = entryData.get("secretKey");
					String encryptedText = null;
					String decryptedText = null;
					byte[] encryptedKey = null;
					byte[] encryptedHash = null;
					byte[] decryptedHash = null;
					byte[] encryptedByteText = null;
					String decryptedKey = null;
					DigitalSeal digitalSeal = new DigitalSeal();
					byte[] H_P = null;
					byte[] calculatedH_P = null;
					KeyPair keyPair = null;
					int keySize = keyAlgorithmKeySize;
					KeyPairGenerator keyPairGenerator;
					try {
						keyPairGenerator = KeyPairGenerator.getInstance("RSA");
						keyPairGenerator.initialize(keySize);
						// generates new key pair(private/public key) every time it's called
						keyPair = keyPairGenerator.genKeyPair();
					} catch (NoSuchAlgorithmException e2) {
						e2.printStackTrace();
					}
					if (text == null) {
						JOptionPane.showMessageDialog(frmdecryptoApp, "No entry data initialized!");
					} else {
						// digital seal here...
						System.out.println("Original text =" + text);
						try {
							H_P = hashText(text);
							// for SHA-512 it says data should not be longer than 117 bytes...
							System.out.println("Original hash =" + new String(H_P));
							encryptedHash = encryptRSAforHash(H_P, keyPair.getPrivate());
							System.out.println("Encrypted hash =" + new String(encryptedHash));

						} catch (Exception e1) {
							e1.printStackTrace();
						}
						if (textAlgorithm.equals("AES")) {
							encryptedText = encryptAES(text, secretKey);
							System.out.println("Encrypted text =" + encryptedText);
							try {
								System.out.println("Secret key =" + new String(keyAESTest.getEncoded()));
								encryptedKey = encryptRSA(new String(keyAESTest.getEncoded()), keyPair.getPublic());
								System.out.println("Encrypted key =" + new String(encryptedKey));
								decryptedKey = new String(decryptRSA(keyPair.getPrivate(), encryptedKey));
								System.out.println("Decrypted key =" + decryptedKey);
								decryptedText = decryptAES(encryptedText, decryptedKey);
								System.out.println("Decrypted text =" + decryptedText);
							} catch (Exception e1) {
								e1.printStackTrace();
							}
						} else if (textAlgorithm.equals("3DES")) {
							try {
								encryptedByteText = encrypt3DES(text, secretKey);
								encryptedText = new String(encryptedByteText);
								System.out.println("Encrypted text =" + encryptedText);
								System.out.println("Secret key =" + secretKey);
								encryptedKey = encryptRSA(secretKey, keyPair.getPublic());
								System.out.println("Encrypted key =" + new String(encryptedKey));
								decryptedKey = new String(decryptRSA(keyPair.getPrivate(), encryptedKey));
								System.out.println("Decrypted key =" + decryptedKey);
								decryptedText = decrypt3DES(encryptedByteText, decryptedKey);
								System.out.println("Decrypted text =" + decryptedText);
							} catch (Exception ef) {
								ef.printStackTrace();
							}

						}

						try {
							decryptedHash = decryptRSAForHash(encryptedHash, keyPair.getPublic());
							calculatedH_P = hashText(text);
						} catch (Exception e1) {
							e1.printStackTrace();
						}
						System.out.println("Decrypted hash is =" + new String(decryptedHash));
						if (new String(calculatedH_P).equals(new String(decryptedHash))) {
							System.out
									.println("Hash is identycal to the calculated one! It really came from my friend!");
						}
						digitalSeal.setEncryptedKey(encryptedKey);
						digitalSeal.setEncryptedText(encryptedText);
						digitalSeal.setEncryptedHash(encryptedHash);
						System.out.println(digitalSeal.toString());
						System.out.println("------------------------------------------------");
					}
				}
			}
		});
		btnCreateDigitalSeal.setBounds(431, 232, 194, 23);
		frmdecryptoApp.getContentPane().add(btnCreateDigitalSeal);

		final JPanel panel_1 = new JPanel();
		panel_1.setBounds(0, 121, 625, 98);
		frmdecryptoApp.getContentPane().add(panel_1);
		panel_1.setLayout(null);

		JLabel lblSelectEntryFile = new JLabel("Select entry file : ");
		lblSelectEntryFile.setBounds(120, 41, 147, 14);
		panel_1.add(lblSelectEntryFile);

		JButton btnOpenFile = new JButton("Open file...");
		btnOpenFile.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				JFileChooser chooser = new JFileChooser();
				panel_1.add(chooser);
				FileNameExtensionFilter filter = new FileNameExtensionFilter("Text files only", "txt");
				chooser.setFileFilter(filter);
				chooser.setCurrentDirectory(new File("src/main/java"));
				int returnVal = chooser.showOpenDialog(panel_1);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					// for now we have keys = {text,secretKey}
					Scanner sc = null;
					try {
						String line = null;
						sc = new Scanner(chooser.getSelectedFile());
						String key = "";
						String value = "";
						while (sc.hasNextLine()) {
							line = sc.nextLine();
							if (line.contains("=")) {
								if (key.length() != 0) {
									value = value.substring(0, value.length() - 1);
									entryData.put(key, value);
									key = "";
									value = "";
								}
								String[] parts = line.split("=");
								key = parts[0];
								for (int i = 1; i < parts.length; i++) {
									value += parts[i] + "\n";
								}
							} else {
								value += line + "\n";
							}
							if (!sc.hasNextLine()) {
								entryData.put(key, value);
							}
						}
					} catch (FileNotFoundException e) {
						e.printStackTrace();
					} finally {
						sc.close();
					}
					JOptionPane.showMessageDialog(frmdecryptoApp, "Entry data initialized. Ready to encrypt!");
				}
			}
		});
		btnOpenFile.setBounds(234, 37, 166, 23);
		panel_1.add(btnOpenFile);

		JLabel lblReadwriteFiles = new JLabel("Read/Write Files");
		lblReadwriteFiles.setFont(new Font("Segoe Print", Font.BOLD, 16));
		lblReadwriteFiles.setBounds(234, 11, 155, 14);
		panel_1.add(lblReadwriteFiles);

		JLabel lblOutputFileCurrently = new JLabel(
				"Output file currently in source folder,needs update to modify path");
		lblOutputFileCurrently.setFont(new Font("Segoe Print", Font.BOLD, 16));
		lblOutputFileCurrently.setBounds(41, 66, 605, 21);
		panel_1.add(lblOutputFileCurrently);
	}

	public static String encryptAES(String text, String secretKey) {

		String encodedText = null;
		try {
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			Cipher cipher = Cipher.getInstance(textAlgorithm + "/" + cipherMode + "/PKCS5Padding");
			if (cipherMode.equals("CBC") || cipherMode.equals("CTR")) {
				cipher.init(Cipher.ENCRYPT_MODE, keyAESTest, iv);
			} else {
				cipher.init(Cipher.ENCRYPT_MODE, keyAESTest);
			}
			encodedText = Base64.getEncoder().encodeToString(cipher.doFinal(text.getBytes("UTF-8")));
			return encodedText;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String decryptAES(String text, String secretKey) {
		String decodedText = null;
		try {
			IvParameterSpec iv = new IvParameterSpec(new byte[16]);
			Cipher cipher = Cipher.getInstance(textAlgorithm + "/" + cipherMode + "/PKCS5Padding");
			if (cipherMode.equals("CBC") || cipherMode.equals("CTR")) {
				cipher.init(Cipher.DECRYPT_MODE, keyAESTest, iv);
			} else {
				cipher.init(Cipher.DECRYPT_MODE, keyAESTest);
			}
			decodedText = new String(cipher.doFinal(Base64.getDecoder().decode(text)));
			return decodedText;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] encryptRSA(String secretKey, PublicKey publicKey) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			return cipher.doFinal(secretKey.getBytes());
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] encryptRSAforHash(byte[] secretKey, PrivateKey privateKey) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			return cipher.doFinal(secretKey);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] decryptRSAForHash(byte[] encrypted, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		return cipher.doFinal(encrypted);
	}

	public static byte[] decryptRSA(PrivateKey privateKey, byte[] encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return cipher.doFinal(encrypted);
	}

	public static byte[] encrypt3DES(String message, String secretKey) throws Exception {

		MessageDigest md = MessageDigest.getInstance("md5");
		byte[] digestOfKey = md.digest(secretKey.getBytes("utf-8"));
		byte[] keyBytes = Arrays.copyOf(digestOfKey, 24);
		for (int j = 0, k = 16; j < 8;) {
			keyBytes[k++] = keyBytes[j++];
		}
		if (textAlgorithmKeySize != 168) {
			// K3 = K1 ,napravi da zadnjih 8 bajtova budu isti od ovih prvih 8 i to je
			// to,samo je jos jedna opcija to da je 112 bitova...
			int firstKeyIndex = 0;
			for (int i = keyBytes.length - 8; i <= keyBytes.length - 1; i++) {
				keyBytes[i] = keyBytes[firstKeyIndex++];
			}
		}
		SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		Cipher cipher = Cipher.getInstance("DESede/" + cipherMode + "/PKCS5Padding");
		if (cipherMode.equals("CBC") || cipherMode.equals("CTR")) {
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, key);
		}
		byte[] plainTextBytes = message.getBytes("utf-8");
		byte[] cipherText = cipher.doFinal(plainTextBytes);

		return cipherText;
	}

	public String decrypt3DES(byte[] message, String secretKey) throws Exception {
		MessageDigest md = MessageDigest.getInstance("md5");
		byte[] digestOfKey = md.digest(secretKey.getBytes("utf-8"));
		byte[] keyBytes = Arrays.copyOf(digestOfKey, 24);
		for (int j = 0, k = 16; j < 8;) {
			keyBytes[k++] = keyBytes[j++];
		}
		if (textAlgorithmKeySize != 168) {
			// K3 = K1 ,napravi da zadnjih 8 bajtova budu isti od ovih prvih 8 i to je
			// to,samo je jos jedna opcija to da je 112 bitova...
			int firstKeyIndex = 0;
			for (int i = keyBytes.length - 8; i <= keyBytes.length - 1; i++) {
				keyBytes[i] = keyBytes[firstKeyIndex++];
			}
		}
		SecretKey key = new SecretKeySpec(keyBytes, "DESede");
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);
		Cipher decipher = Cipher.getInstance("DESede/" + cipherMode + "/PKCS5Padding");
		if (cipherMode.equals("CBC") || cipherMode.equals("CTR")) {
			decipher.init(Cipher.DECRYPT_MODE, key, iv);
		} else {
			decipher.init(Cipher.DECRYPT_MODE, key);
		}
		byte[] plainText = decipher.doFinal(message);
		return new String(plainText, "UTF-8");
	}

	private static byte[] hashText(String text) throws UnsupportedEncodingException {
		MessageDigest md = null;
		byte[] textHash = null;
		if (!hashFunction.equals("SHA-1")) {
			hashFunction = hashFunction.substring(0, 3) + "-" + String.valueOf(hashFunctionDigestSize);
		}
		try {
			md = MessageDigest.getInstance(hashFunction);
			SecureRandom random = new SecureRandom();
			byte[] initVector = new byte[16];
			random.nextBytes(initVector);
			textHash = md.digest(text.getBytes(StandardCharsets.UTF_8));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return textHash;
	}
}
