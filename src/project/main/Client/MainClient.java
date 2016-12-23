package project.main.Client;

import com.sun.nio.sctp.IllegalReceiveException;
import project.main.Server.ClientInfo;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

public class MainClient {
	private static DatagramSocket socketToServer;
	private static DatagramSocket socketToFriend;
	private static String myLabel;
	private static String myKey;
	private static InetAddress serverIp;
	private static int servPort;
	private static String myIpString;
	private static int myPort;
	private static int myPortForMessages;
	private static Key publicKey;
	private static Key privateKey;
	private static KeyFactory kfac;
	private static byte[] myEncodedPublicKey;
	
	public static void main(String[] args) throws Exception{
		init(args);
		initEncription();
		getPublicKeyFromEncoded(myEncodedPublicKey);
		RSAPublicKeySpec keyspec = kfac.getKeySpec(publicKey, RSAPublicKeySpec.class);
		
		List<String> regOnServerMessage = Arrays.asList("Hi", myLabel, keyspec.getModulus().toString(), keyspec.getPublicExponent().toString());
		
		sendMessage(socketToServer, serverIp, servPort, regOnServerMessage);
		
		DatagramPacket packet = getRandomFromServer();
		byte[] input = packet.getData();
		byte[] encryptedData = new byte[128];
		
		System.arraycopy(input,0,encryptedData,0,encryptedData.length);
		String decryptedMessage = decryptMessageWithPrivateKey(encryptedData);
		String received = new String(input, 128, input.length-128);
		String[] splited = received.split(" ");
		Key serverPublicKey = getKeyFromSpec(splited[0], splited[1]);
		byte[] encodedMessageRandom = encryptMessage(decryptedMessage, serverPublicKey);
		
		String s = concatMessage(Arrays.asList(myLabel, myIpString, myPortForMessages + ""));
		byte[] info = encryptMessage(s , serverPublicKey);
		byte[] b2 = mergeByteArrays(encodedMessageRandom, info);
		
		String pubKey = concatMessage(Arrays.asList(keyspec.getModulus().toString(), keyspec.getPublicExponent().toString()));
		byte[] b3 = mergeByteArrays(b2, pubKey.getBytes());
		sendEncodedMessage(socketToServer, serverIp, servPort, b3);
		System.out.println("Secure reg on server finished");
		
//		new Thread(() -> {
//			waitForMessage();
//		}).start();
//
		if(isUserWannaConnect()){
			String userLabel = getUserInput("Please input name of User you want connect to");
			ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, myPort, userLabel);

			List<String> sayHi = Arrays.asList("Hi", myLabel);
			sendMessage(socketToFriend, targetUserInfo.getIp(), targetUserInfo.getPort(), sayHi);
			//starting chat
			startingChat(targetUserInfo);
			return;
		}
	}
	
	private static byte[] mergeByteArrays(byte[] one, byte[] two) {
		byte[] combined = new byte[one.length + two.length];
		
		System.arraycopy(one,0,combined,0         ,one.length);
		System.arraycopy(two,0,combined,one.length,two.length);
		return combined;
	}
	
	private static Key getKeyFromSpec(String s1, String s2) throws InvalidKeySpecException {
		s2=s2.trim();
		return kfac.generatePublic(
				new RSAPublicKeySpec(
						new BigInteger(s1),
						new BigInteger(s2)));
	}
	private static DatagramPacket getRandomFromServer() {
		byte[] bufor = new byte[512];
		DatagramPacket packet = new DatagramPacket(bufor, bufor.length);
		try{
			// odbierz pakiet
			socketToServer.receive(packet);
		} catch(IOException e) {
			System.err.println("Błąd przy odbieraniu pakietu: " + e);
			System.exit(1);
		}
		// wypisz co dostałeś
		return packet;
	}
	
	private static void initEncription() throws NoSuchAlgorithmException {
		KeyPairGenerator kpairg = KeyPairGenerator.getInstance("RSA");
		kpairg.initialize(1024);
		KeyPair kpair = kpairg.genKeyPair();
		publicKey = kpair.getPublic();
		privateKey = kpair.getPrivate();
		//Encode a version of the public key in a byte-array
		myEncodedPublicKey = kpair.getPublic().getEncoded();
		//Key factory, for key-key specification transformations
		kfac = KeyFactory.getInstance("RSA");
	}
	
	private static String decryptMessageWithPrivateKey(byte[] encodedMessage) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		//Decoding using private key
		Cipher cipherDecode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecode.init(Cipher.DECRYPT_MODE, privateKey);
		String decodedMessage = new
		String(cipherDecode.doFinal(encodedMessage));
		return decodedMessage;
	}
	
	private static byte[] encryptMessage(String message, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// ---- Using RSA Cipher to encode simple messages ----
		//Encoding using public key. Warning - ECB is unsafe.
		Cipher cipherEncode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherEncode.init(Cipher.ENCRYPT_MODE, key);
		return cipherEncode.doFinal(message.getBytes());
	}
	
	private static Key getPublicKeyFromEncoded(byte[] encodedPublicKey) throws InvalidKeySpecException {
		//Building public key from the byte-array
		X509EncodedKeySpec ksp = new X509EncodedKeySpec(encodedPublicKey);
		return kfac.generatePublic(ksp);
	}
	
	private static void init(String[] args) throws SocketException {
		myLabel = args[0];
		System.out.println("CLIENT " + myLabel);
		myKey = args[1];
		serverIp = getIpByName(args[2]);
		servPort = Integer.parseInt(args[3]);
		InetAddress myIp = getIpByName(args[4]);
		myIpString = args[4];
		myPort = Integer.parseInt(args[5]);
		myPortForMessages = Integer.parseInt(args[6]);
		socketToFriend = new DatagramSocket(myPortForMessages);
		socketToServer = new DatagramSocket(myPort);
	}
	
	private static ClientInfo askServerForUser(InetAddress serverIp, int servPort, int myPort, String userLabel) {
		List<String> getInfo = Arrays.asList("Give", userLabel);
		sendMessage(socketToServer, serverIp, servPort, getInfo);
		return getTargetUserInfo();
	}
	
	private static InetAddress getIpByName(String arg) {
		try {
			return InetAddress.getByName(arg);
		} catch (UnknownHostException e) {
			e.printStackTrace();
			
		}
		try {
			return InetAddress.getByName("localhost");
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;
	}
	
//	private static void waitForMessage() {
//		System.out.println("------Waitformessage");
//		while (true) {
//			String received = getMessage(socketToFriend);
//			String[] splited = received.split(" ");
//			switch (splited[0]) {
//				case "msg:":
//					System.out.println(Arrays.toString(splited));
//					break;
//				case "Hi":
//					ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, myPort, splited[1]);
//					new Thread(() -> startingChat(targetUserInfo)).start();
//					break;
//			}
//		}
//	}
	
	private static ClientInfo getTargetUserInfo() {
		String received = getMessage(socketToServer);
		String[] splited = received.split(" ");
		System.out.println(Arrays.toString(splited));
		if (splited[0].equals("NoSuchUser"))
			throw new IllegalReceiveException();
		InetAddress ip = null;
		try {
			ip = InetAddress.getByName(splited[1]);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		int port = Integer.parseInt(splited[2]);
		return new ClientInfo(publicKey, ip, port);
	}
	
	private static String getMessage(DatagramSocket socket) {
		byte[] bufor = new byte[256];
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
		System.out.println(Thread.currentThread().toString() + "Odebrałem: " + received);
		return received;
	}
	
	private static String getUserInput(String messageToUser) {
		System.out.println(messageToUser);
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String message = "";
		try {
			return br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return message;
	}
	
	private static boolean isUserWannaConnect() {
		System.out.println("Do you want connect to somewone? yes/no");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String wannaConnect = "";
		try {
			wannaConnect = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return wannaConnect.equals("yes");
	}
	
	private static void sendEncodedMessage(DatagramSocket socket, InetAddress serverAdress, int serverPort, byte... messages) {
		DatagramPacket packet = new DatagramPacket(messages, messages.length, serverAdress, serverPort);
		trySendPacket(socket, packet);
		
	}
	
	private static void trySendPacket(DatagramSocket socket, DatagramPacket packet) {
		// wyślij pakiet
		try {
			socket.send(packet);
		} catch(IOException e) {
			System.err.println("Problem z odesłaniem pakietu: " + e);
			System.exit(1);
		}
	}
	
	private static void sendMessage(DatagramSocket socket, InetAddress serverAdress, int serverPort, List<String> args) {
		String messageToSend = concatMessage(args);
		
		byte[] bufor = messageToSend.getBytes();
		
		DatagramPacket packet = new DatagramPacket(bufor, bufor.length, serverAdress, serverPort);
		trySendPacket(socket, packet);
	}
	
	private static String concatMessage(List<String> args) {
		String messageToSend = "";
		for (String arg : args) {
			messageToSend += arg + " ";
		}
		return messageToSend;
	}
	
	
	
	private static void sendPacket(DatagramSocket socket, DatagramPacket packet) {
		try{
			if (true)
			System.out.println("Próbuję odesłać pakiet");
			// odeślij go do odbiorcy
			socket.send(packet);
			System.out.println("Odesłano");
		} catch(IOException e) {
			System.err.println("Problem z odesłaniem pakietu: " + e);
			System.exit(1);
		}
	}
	
	private static void startingChat(ClientInfo targetUserInfo) {
		while (true) {
			String inputedMessage = getUserInput("Enter message");
			if (inputedMessage.equals("exit"))
				System.exit(1);
			List<String> msgToSend = Arrays.asList("msg: ", inputedMessage);
			System.out.println("Sending packet to " + targetUserInfo.getIp() + " port "+ targetUserInfo.getPort() + " msgToSend " + msgToSend);
			sendMessage(socketToFriend, targetUserInfo.getIp(), targetUserInfo.getPort(), msgToSend);
		}
	}
}
