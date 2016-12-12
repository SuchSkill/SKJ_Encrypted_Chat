package main.Client;

import com.sun.nio.sctp.IllegalReceiveException;
import main.Server.ClientInfo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.util.Arrays;
import java.util.List;

public class MainClient {
	private static DatagramPacket packet = null;
	private static DatagramSocket socket;
	private static String myLabel;
	private static String myKey;
	private static InetAddress serverIp;
	private static int servPort;
	private static String myIpString;
	private static int myPort;
	private static ClientInfo targetUserInfo;
	
	public static void main(String[] args) {
		myLabel = args[0];
		System.out.println("CLIENT" + myLabel);
		myKey = args[1];
		serverIp = getIpByName(args[2]);
		servPort = Integer.parseInt(args[3]);
		InetAddress myIp = getIpByName(args[4]);
		myIpString = args[4];
		myPort = Integer.parseInt(args[5]);
		
		List<String> regOnServer = Arrays.asList("Hi", myLabel, myKey, myIpString, myPort +"");
		sendMessage(myPort, serverIp, servPort, regOnServer);
		
		new Thread(() -> {
			waitForMessage();
		});
		
		if(isUserWannaConnect()){
			String userLabel = getUserInput("Please input name of User you want connect to");
			ClientInfo targetUserInfo = askServerForUser(serverIp, servPort, myPort, userLabel);
			
			List<String> sayHi = Arrays.asList("Hi", myLabel);
			sendMessage(myPort, targetUserInfo.getIp(), targetUserInfo.getPort(), sayHi);
			//starting chat
			while (true) {
				String inputedMessage = getUserInput("Enter message");
				if (inputedMessage.equals("exit"))
					System.exit(1);
				List<String> msgToSend = Arrays.asList("msg:", inputedMessage);
				
				sendMessage(myPort, targetUserInfo.getIp(), targetUserInfo.getPort(), msgToSend);
			}
		}
		
		socket.close();
	}
	
	private static ClientInfo askServerForUser(InetAddress serverIp, int servPort, int myPort, String userLabel) {
		List<String> getInfo = Arrays.asList("Give", userLabel);
		sendMessage(myPort, serverIp, servPort, getInfo);
		return getTargetUserInfo();
	}
	
	private static ClientInfo getTargetUserInfo() {
		String received = getMessage();
		String[] splited = received.split(" ");
		System.out.println(Arrays.toString(splited));
		if (splited[0].equals("NoSuchUser"))
			throw new IllegalReceiveException();
		InetAddress ip = null;
		try {
			ip = InetAddress.getByName(splited[2]);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		int port = Integer.parseInt(splited[3]);
		return new ClientInfo(splited[1], ip, port);
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
		String received = getMessage();
		
		String[] splited = received.split(" ");
		System.out.println(Arrays.toString(splited));
		switch (splited[0]) {
			case "msg:":
				System.out.println(Arrays.toString(splited));
				
				break;
			case "hi":
				targetUserInfo = askServerForUser(serverIp, servPort, myPort, splited[1]);
				break;
		}
	}
	
	private static String getMessage() {
		byte[] bufor = new byte[256];
		packet = new DatagramPacket(bufor, bufor.length);
		try{
			if (true){}//avoid ide code error duplication(with server)
			System.out.println("Czekam na pakiet");
			// odbierz pakiet
			socket.receive(packet);
		} catch(IOException e) {
			System.err.println("Błąd przy odbieraniu pakietu: " + e);
			System.exit(1);
		}
		// wypisz co dostałeś
		String received = new String(packet.getData(), 0, packet.getLength());
		System.out.println("Odebrałem: " + received);
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
	
	private static void sendMessage(int fromPort, InetAddress serverAdress, int port, List<String> args) {
		int serverPort = port;
		
		try {
			System.out.println("Próbuję utowrzyć gniazdo");
			socket = new DatagramSocket(fromPort);
			System.out.println("Gniazdo utworzone");
		} catch(SocketException e) {
			System.err.println("Błąd przy tworzeniu gniazda: " + e);
			System.exit(1);
		}
		String messageToSend = "";
		for (String arg : args) {
			messageToSend += arg + " ";
		}
		byte[] bufor = messageToSend.getBytes();
		packet = new DatagramPacket(bufor, bufor.length, serverAdress, serverPort);
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
}
