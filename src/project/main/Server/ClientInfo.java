package project.main.Server;

import java.net.InetAddress;
import java.security.Key;

/**
 * Created by Eugene on 11.12.2016.
 */
public class ClientInfo {
	private Key key;
	private InetAddress ip;
	private int port;
	
	@Override
	public String toString() {
		return "ClientInfo{" +
				"key='" + key + '\'' +
				", ip=" + ip +
				", port=" + port +
				'}';
	}
	
	public Key getKey() {
		return key;
	}
	
	public void setKey(Key key) {
		this.key = key;
	}
	
	public InetAddress getIp() {
		return ip;
	}
	
	public void setIp(InetAddress ip) {
		this.ip = ip;
	}
	
	public int getPort() {
		return port;
	}
	
	public void setPort(int port) {
		this.port = port;
	}
	
	public ClientInfo(Key key, InetAddress ip, int port) {
	
		this.key = key;
		this.ip = ip;
		this.port = port;
	}
}
