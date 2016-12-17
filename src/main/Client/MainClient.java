package main.Client;

import com.sun.nio.sctp.IllegalReceiveException;
import main.Server.ClientInfo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.util.Arrays;
import java.util.List;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;

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
	
	public static void main(String[] args) throws Exception{
		init(args);
		
		List<String> regOnServerMessage = Arrays.asList("Hi", myLabel, myKey, myIpString, myPortForMessages +"");
		sendMessage(socketToServer, serverIp, servPort, regOnServerMessage);
		
		KeyPairGenerator kpairg = KeyPairGenerator.getInstance("RSA");
		kpairg.initialize(1024);
		KeyPair kpair = kpairg.genKeyPair();
		publicKey = kpair.getPublic();
		privateKey = kpair.getPrivate();
		//Key factory, for key-key specification transformations
		KeyFactory kfac = KeyFactory.getInstance("RSA");
		//Generate plain-text key specification
		RSAPublicKeySpec keyspec = kfac.getKeySpec(publicKey, RSAPublicKeySpec.class);
		System.out.println("Public key, RSA modulus: " +
				keyspec.getModulus() + "\n" +
				"exponent: " +
				keyspec.getPublicExponent() + "\n");
		//Building public key from the plain-text specification
		Key recoveredPublicFromSpec = kfac.generatePublic(keyspec);
		//Encode a version of the public key in a byte-array
		System.out.print("Public key encoded in " +
				kpair.getPublic().getFormat() + " format: ");
		byte[] encodedPublicKey = kpair.getPublic().getEncoded();
		System.out.println(Arrays.toString(encodedPublicKey) + "\n");
		
		//Building public key from the byte-array
		X509EncodedKeySpec ksp = new X509EncodedKeySpec(encodedPublicKey);
		Key recoveredPublicFromArray = kfac.generatePublic(ksp);
		// ---- Using RSA Cipher to encode simple messages ----
		//Encoding using public key. Warning - ECB is unsafe.
		String message = "Please encode me now!";
		Cipher cipherEncode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherEncode.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encodedMessage = cipherEncode.doFinal(message.getBytes());
		System.out.println("Encoded \"" + message + "\" as: " +
				Arrays.toString(encodedMessage) + "\n");
		//Decoding using private key
		Cipher cipherDecode = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipherDecode.init(Cipher.DECRYPT_MODE, privateKey);
		String decodedMessage = new
				String(cipherDecode.doFinal(encodedMessage));
		System.out.println("Decoded: " + decodedMessage);
		
		
		
		
		
		
		new Thread(() -> {
			waitForMessage();
		}).start();
		if(isUserWannaConnect()){
			String userLabel = getUserInput("Please input name of User you want connect to");
			ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, myPort, userLabel);
			
			List<String> sayHi = Arrays.asList("Hi", myLabel);
			sendMessage(socketToFriend, targetUserInfo.getIp(), targetUserInfo.getPort(), sayHi);
			//starting chat
			startingChat(targetUserInfo);
			return;
		}
		
//		socketToServer.close();
	}
	
	private static void init(String[] args) throws SocketException {
		myLabel = args[0];
		System.out.println("CLIENT" + myLabel);
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
	
	private static void waitForMessage() {
		System.out.println("------Waitformessage");
		while (true) {
			String received = getMessage(socketToFriend);
			String[] splited = received.split(" ");
			switch (splited[0]) {
				case "msg:":
					System.out.println(Arrays.toString(splited));
					break;
				case "Hi":
					ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, myPort, splited[1]);
					new Thread(() -> startingChat(targetUserInfo)).start();
					break;
			}
		}
	}
	
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
		return new ClientInfo(splited[0], ip, port);
	}
	
	private static String getMessage(DatagramSocket socket) {
		byte[] bufor = new byte[256];
		DatagramPacket packet = new DatagramPacket(bufor, bufor.length);
		try{
			System.out.println(Thread.currentThread().toString() + "Czekam na pakiet on " + socket.getPort());
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
	
	private static void sendMessage(DatagramSocket socket, InetAddress serverAdress, int serverPort, List<String> args) {
				
		String messageToSend = "";
		for (String arg : args) {
			messageToSend += arg + " ";
		}
		byte[] bufor = messageToSend.getBytes();
		DatagramPacket packet = new DatagramPacket(bufor, bufor.length, serverAdress, serverPort);
		// wyślij pakiet
		try {
			System.out.println("Próbuję wysłać pakiet");
			socket.send(packet);
			System.out.println("Pakiet wysłany");
		} catch(IOException e) {
			System.err.println("Problem z odesłaniem pakietu: " + e);
			System.exit(1);
		}
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
