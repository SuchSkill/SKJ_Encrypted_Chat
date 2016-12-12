package main.Server;
import java.net.*;
import java.io.*;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Eugene on 10.12.2016.
 */
public class MainServer {
	public static void main(String[] args) {
		// gniazdo do oczekiwania na dane
		DatagramSocket socket = null;
		// pakiet
		DatagramPacket packet;
		Map<String, ClientInfo> datebase = new HashMap<>();
		System.out.println("SERVER");
		// otwórz gniazdo
		try {
			System.out.println("Próbuję utowrzyć gniazdo");
			// utwórz gniazdo
			socket = new DatagramSocket(9999);
			// przestaw w tryb rozgłoszeniowy
			socket.setBroadcast(true);
			System.out.println("Gniazdo utworzone");
		} catch(SocketException e) {
			System.err.println("Błąd przy tworzeniu gniazda: " + e);
			System.exit(1);
		}
		
		while (true) {
			// utwórz pakiet dla odbierania danych
			byte[] bufor = new byte[256];
			packet = new DatagramPacket(bufor, bufor.length);
			try{
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
			//todo parse message
			String[] splited = received.split(" ");
			System.out.println(Arrays.toString(splited));
			switch (splited[0]) {
				case "Hi":
					InetAddress ip = null;
					int port = 0;
					String key = splited[2];
					try {
						ip = InetAddress.getByName(splited[3]);
						port = Integer.parseInt(splited[4]);
					} catch (UnknownHostException e) {
						e.printStackTrace();
					}
					ClientInfo info = new ClientInfo(key, ip, port);
					datebase.put(splited[1], info);
					break;
				case "Give":
					String message = getInfo(datebase.get(splited[1]));
					byte[] bufor1 = message.getBytes();
					packet = new DatagramPacket(bufor1, bufor1.length, packet.getAddress(), packet.getPort());
					sendPacket(socket, packet);
					break;
			}
			System.out.println("DATABASE" + datebase);
			//todo check command
			// pobierz adres i port z odebranego pakietu
//			InetAddress address = packet.getAddress();
//			int port = packet.getPort();
//			System.out.println("z adresu " + address.toString() + ":" + port);
//			int length = packet.getLength();
			
			// teraz odeślemy odpowiedź
			// utwórz nowy pakiet do odesłania
//			packet = new DatagramPacket(bufor, length, address, port);
			
		}
		
	}
	
	private static String getInfo(ClientInfo clientInfo1) {
		ClientInfo clientInfo = clientInfo1;
		String key = clientInfo.getKey();
		InetAddress ip1 = clientInfo.getIp();
		int port1 = clientInfo.getPort();
		return key+ " " + ip1 + " " + port1;
	}
	
	private static void sendPacket(DatagramSocket socket, DatagramPacket packet) {
		try{
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
