package project.main.Server;
import javax.crypto.Cipher;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;


/**
 * Created by Eugene on 10.12.2016.
 */
public class MainServer {
	private static Key privateKey;
	private static KeyFactory kfac;
	private static RSAPublicKeySpec keyspec;
	private static HashMap<String, Integer> regRequest;
	private static DatagramSocket socket;
	private static Map<String, ClientInfo> datebase;
	
	public static void main(String[] args) throws Exception {
		init();
		initEncription();
		
		while (true) {
			// utwórz pakiet dla odbierania danych
			byte[] bufor = new byte[2048];
			DatagramPacket packet = new DatagramPacket(bufor, bufor.length);
			try{
				// odbierz pakiet
				socket.receive(packet);
			} catch(IOException e) {
				System.err.println("Błąd przy odbieraniu pakietu: " + e);
				System.exit(1);
			}
			// wypisz co dostałeś
			String received = new String(packet.getData(), 0, packet.getLength());
			String[] splited = received.split(" ");
			Thread.sleep(100);
			byte[] bufor1;
			String message;
			switch (splited[0]) {
				case "Hi":
					Key recoveredPublicFromSpec = getKeyFromSpec(splited[2], splited[3]);
					byte[] encodedMessage = getEncodedRandom(splited[1], recoveredPublicFromSpec);
					byte[] combined = addPublicKeyToMessage(encodedMessage);
					packet = new DatagramPacket(combined, combined.length, packet.getAddress(), packet.getPort());
					sendPacket(socket, packet);
					break;
				case "Give":
					message = getInfo(datebase.get(splited[1]));
					System.out.println("msg to send: " + message);
					bufor1 = message.getBytes();
					System.out.println("Sending to: " + packet.getAddress()+ " " + packet.getPort());
					packet = new DatagramPacket(bufor1, bufor1.length, packet.getAddress(), packet.getPort());
					sendPacket(socket, packet);
					break;
				default:
					byte[] input = packet.getData();
					byte[] encryptedRandom = new byte[128];
					byte[] encryptedInfo = new byte[128];
					
					System.arraycopy(input,0,encryptedRandom,0,encryptedRandom.length);
					String decryptedRandom = decryptMessageWithPrivateKey(encryptedRandom);
					
					System.arraycopy(input,128,encryptedInfo,0,encryptedInfo.length);
					String decryptedInfo = decryptMessageWithPrivateKey(encryptedInfo);
					String[] decryptedInfoSplitted = decryptedInfo.split(" ");
					
					String pubKey = new String(packet.getData(), 256, packet.getLength()-256);
					String[] pubKeySplitted = pubKey.split(" ");
					
					
					if(regRequest.get(decryptedInfoSplitted[0]) == Integer.parseInt(decryptedRandom)){
						System.out.println("Added new client " + decryptedInfoSplitted[0] + " "
								+ decryptedInfoSplitted[1] + " " + decryptedInfoSplitted[2]);
						Key recoveredPublicFromSpec1 = getKeyFromSpec(pubKeySplitted[0], pubKeySplitted[1]);
						ClientInfo clientInfo = new ClientInfo(recoveredPublicFromSpec1,
								InetAddress.getByName(decryptedInfoSplitted[1]),
								Integer.parseInt(decryptedInfoSplitted[2]));
						datebase.put(decryptedInfoSplitted[0], clientInfo);
						System.out.println(clientInfo);
					}else{
						regRequest.remove(decryptedInfoSplitted[0]);
						System.out.println("Wrong validation for " + regRequest.get(decryptedInfoSplitted[0]));
					}
			}
		}
		
	}
	
	private static void init() {
		// gniazdo do oczekiwania na dane
		socket = null;
		// pakiet
		datebase = new HashMap<>();
		System.out.println("SERVER");
		// otwórz gniazdo
		try {
			// utwórz gniazdo
			socket = new DatagramSocket(9999);
			// przestaw w tryb rozgłoszeniowy
			socket.setBroadcast(true);
		} catch(SocketException e) {
			System.err.println("Błąd przy tworzeniu gniazda: " + e);
			System.exit(1);
		}
		System.out.println("Initialisatin succeed");
	}
	
	private static byte[] addPublicKeyToMessage(byte[] encodedMessage) {
		String message;
		byte[] bufor1;
		message = keyspec.getModulus() + " " + keyspec.getPublicExponent();
		bufor1 = message.getBytes();
		byte[] combined = new byte[encodedMessage.length + bufor1.length];
		System.arraycopy(encodedMessage,0,combined,0,encodedMessage.length);
		System.arraycopy(bufor1,0,combined,encodedMessage.length,bufor1.length);
		return combined;
	}
	
	private static byte[] getEncodedRandom(String label, Key recoveredPublicFromSpec) throws Exception{
		int randomInt = new Random().nextInt(1_000_000_000);
		regRequest.put(label, randomInt);
		return encryptMessage(randomInt+"", recoveredPublicFromSpec);
	}
	
	private static String getInfo(ClientInfo clientInfo1) throws InvalidKeySpecException {
		Key key = clientInfo1.getKey();
		RSAPublicKeySpec keyspec = kfac.getKeySpec(key, RSAPublicKeySpec.class);
		String ip1 = clientInfo1.getIp().getHostAddress();
		System.out.println(ip1);
		int port1 = clientInfo1.getPort();
		System.out.println(keyspec.getModulus().toString());
		System.out.println(keyspec.getPublicExponent().toString());
		return ip1 + " " + port1+ " " + keyspec.getModulus().toString() +" "+ keyspec.getPublicExponent().toString();
	}
	
	
	private static void sendPacket(DatagramSocket socket, DatagramPacket packet) {
		try{
			// odeślij go do odbiorcy
			socket.send(packet);
		} catch(IOException e) {
			System.err.println("Problem z odesłaniem pakietu: " + e);
			System.exit(1);
		}
	}
	
	private static void initEncription() throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyPairGenerator kpairg = KeyPairGenerator.getInstance("RSA");
		kpairg.initialize(1024);
		KeyPair kpair = kpairg.genKeyPair();
		privateKey = kpair.getPrivate();
		//Key factory, for key-key specification transformations
		kfac = KeyFactory.getInstance("RSA");
		//Encode a version of the public key in a byte-array
		keyspec = kfac.getKeySpec(kpair.getPublic(), RSAPublicKeySpec.class);
		regRequest = new HashMap<>();
	}
	private static byte[] encryptMessage(String message, Key key) throws Exception{
		// ---- Using RSA Cipher to encode simple messages ----
		//Encoding using public key. Warning - ECB is unsafe.
		Cipher cipherEncode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherEncode.init(Cipher.ENCRYPT_MODE, key);
		return cipherEncode.doFinal(message.getBytes());
	}
	private static String decryptMessageWithPrivateKey(byte[] encodedMessage) throws Exception{
		//Decoding using private key
		Cipher cipherDecode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecode.init(Cipher.DECRYPT_MODE, privateKey);
		return new String(cipherDecode.doFinal(encodedMessage));
	}
	private static Key getKeyFromSpec(String s1, String s2) throws InvalidKeySpecException {
		s2=s2.trim();
		return kfac.generatePublic(
				new RSAPublicKeySpec(
						new BigInteger(s1),
						new BigInteger(s2)));
	}
}
