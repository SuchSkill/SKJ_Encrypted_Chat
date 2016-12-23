package project.main.Client;

import com.sun.nio.sctp.IllegalReceiveException;
import project.main.Server.ClientInfo;

import javax.crypto.Cipher;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainClient {
	private static DatagramSocket socketToServer;
	private static DatagramSocket socketToFriend;
	private static String myLabel;
	private static InetAddress serverIp;
	private static int servPort;
	private static String myIpString;
	private static int myPortForMessages;
	private static Key publicKey;
	private static Key privateKey;
	private static KeyFactory kfac;
	private static Map<String, ClientInfo> friendList;
	
	public static void main(String[] args) throws Exception{
		init(args);
		initEncription();
		regOnServ();
		
		startRecivingMessageThread();
		
		if(isUserWannaConnect()){
			String userLabel = getUserInput("Please input name of User you want connect to");
			ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, userLabel);
			friendList.put(userLabel, targetUserInfo);
			sayHi(targetUserInfo);
			//starting chat loop
			startingChat(userLabel);
		}
	}
	
	private static void startRecivingMessageThread() {
		new Thread(() -> {
			try {
				waitForMessage();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}).start();
	}
	
	private static void sayHi(ClientInfo targetUserInfo) throws Exception{
		System.out.println("Saying hi to ");
		System.out.println(targetUserInfo.getIp());
		System.out.println(targetUserInfo.getPort());
		String sayHi = "Hi " + myLabel;
		byte[] encriptedHi = encryptMessage(sayHi, targetUserInfo.getKey());
		sendEncodedMessage(socketToFriend, targetUserInfo.getIp(), targetUserInfo.getPort(), encriptedHi);
	}
	
	private static void regOnServ() throws Exception{
		RSAPublicKeySpec keyspec = kfac.getKeySpec(publicKey, RSAPublicKeySpec.class);
		
		List<String> regOnServerMessage = Arrays.asList("Hi", myLabel,
				keyspec.getModulus().toString(), keyspec.getPublicExponent().toString());
		
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
		
		String pubKey = concatMessage(Arrays.asList(keyspec.getModulus().toString(),
				keyspec.getPublicExponent().toString()));
		byte[] b3 = mergeByteArrays(b2, pubKey.getBytes());
		sendEncodedMessage(socketToServer, serverIp, servPort, b3);
		System.out.println("Secure reg on server finished");
	}
	
	private static byte[] mergeByteArrays(byte[] one, byte[] two) {
		byte[] combined = new byte[one.length + two.length];
		System.arraycopy(one,0,combined,0,one.length);
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
		//Key factory, for key-key specification transformations
		kfac = KeyFactory.getInstance("RSA");
	}
	
	private static String decryptMessageWithPrivateKey(byte[] encodedMessage) throws Exception{
		//Decoding using private key
		Cipher cipherDecode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecode.init(Cipher.DECRYPT_MODE, privateKey);
		return new	String(cipherDecode.doFinal(encodedMessage));
	}
	
	private static byte[] encryptMessage(String message, Key key) throws Exception{
		// ---- Using RSA Cipher to encode simple messages ----
		//Encoding using public key. Warning - ECB is unsafe.
		Cipher cipherEncode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherEncode.init(Cipher.ENCRYPT_MODE, key);
		return cipherEncode.doFinal(message.getBytes());
	}
	
	
	private static void init(String[] args) throws SocketException {
		myLabel = args[0];
		System.out.println("CLIENT " + myLabel);
		serverIp = getIpByName(args[1]);
		servPort = Integer.parseInt(args[2]);
		myIpString = args[3];
		int myPort = Integer.parseInt(args[4]);
		myPortForMessages = Integer.parseInt(args[5]);
		socketToFriend = new DatagramSocket(myPortForMessages);
		socketToServer = new DatagramSocket(myPort);
		friendList = new HashMap<>();
	}
	
	private static ClientInfo askServerForUser(InetAddress serverIp, int serverPort, String userLabel)
			throws InvalidKeySpecException {
		List<String> getInfo = Arrays.asList("Give", userLabel);
		System.out.println("Give " + userLabel);
		sendMessage(socketToServer, serverIp, serverPort, getInfo);
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
	
	private static void waitForMessage() throws Exception {
		while (true) {
			DatagramPacket rowDatagramPacket = getRowDatagramPacket(socketToFriend, 128);
			String received = decryptMessageWithPrivateKey(rowDatagramPacket.getData());
			String[] splited = received.split(" ");
			switch (splited[0]) {
				case "msg:":
					System.out.println(Arrays.toString(splited));
					if(splited[1].equals("newKeys")){
						Thread.sleep(500);
						System.out.println("friend info updated");
						String userLabel1 = splited[2];
						friendList.put(userLabel1, askServerForUser(serverIp, servPort, userLabel1));
					}
					break;
				case "Hi":
					String userLabel = splited[1];
					ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, userLabel);
					friendList.put(userLabel, targetUserInfo);
					System.out.println("Starting new chatting thread with " + userLabel);
					new Thread(() -> {
						try {
							startingChat(userLabel);
						} catch (Exception e) {
							e.printStackTrace();
						}
					}).start();
					break;
			}
		}
	}
	
	private static ClientInfo getTargetUserInfo() throws InvalidKeySpecException {
		String received = getMessage(socketToServer);
		String[] splited = received.split(" ");
		System.out.println(Arrays.toString(splited));
		if (splited[0].equals("NoSuchUser"))
			throw new IllegalReceiveException();
		InetAddress ip = null;
		try {
			ip = InetAddress.getByName(splited[0]);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		int port = Integer.parseInt(splited[1]);
		Key key = getKeyFromSpec(splited[2], splited[3]);
		
		return new ClientInfo(key, ip, port);
	}
	
	private static String getMessage(DatagramSocket socket) {
		DatagramPacket packet = getRowDatagramPacket(socket, 1024);
		// wypisz co dostałeś
		String received = new String(packet.getData(), 0, packet.getLength());
//		System.out.println(Thread.currentThread().toString() + "Odebrałem: " + received);
		return received;
	}
	
	private static DatagramPacket getRowDatagramPacket(DatagramSocket socket, int buffSize) {
		byte[] bufor = new byte[buffSize];
		DatagramPacket packet = new DatagramPacket(bufor, bufor.length);
		try{
			// odbierz pakiet
			socket.receive(packet);
		} catch(IOException e) {
			System.err.println("Błąd przy odbieraniu pakietu: " + e);
			System.exit(1);
		}
		return packet;
	}
	
	private static String getUserInput(String messageToUser) {
		System.out.println(messageToUser);
		InputStream in = System.in;
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
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
	
	private static void sendEncodedMessage(DatagramSocket socket, InetAddress serverAdress,
	                                       int serverPort, byte... messages) {
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
	
	private static void sendMessage(DatagramSocket socket, InetAddress serverAdress,
	                                int serverPort, List<String> args) {
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
	
	
	private static void startingChat(String label) throws Exception {
		while (!Thread.currentThread().isInterrupted()) {
			String inputedMessage = getUserInput("Enter message");
			if (inputedMessage.equals("exit"))
				System.exit(1);
			ClientInfo clientInfo = friendList.get(label);
			if (inputedMessage.equals("newKeys")){
				initEncription();
				regOnServ();
				inputedMessage += " "+ myLabel;
			}
			byte[] encryptedMsg = encryptMessage("msg: "+ inputedMessage, clientInfo.getKey());
			System.out.println("Sending packet to " + clientInfo.getIp()
					+ " port "+ clientInfo.getPort() + " msgToSend " + inputedMessage);
			sendEncodedMessage(socketToFriend, clientInfo.getIp(), clientInfo.getPort(), encryptedMsg);
			
		}
		System.out.println("End of chatting thread");
	}
}
