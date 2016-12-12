package main.Server;

import java.net.InetAddress;

/**
 * Created by Eugene on 11.12.2016.
 */
public class ClientInfo {
	private String key;
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
	
	public String getKey() {
		return key;
	}
	
	public void setKey(String key) {
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
	
	public ClientInfo(String key, InetAddress ip, int port) {
	
		this.key = key;
		this.ip = ip;
		this.port = port;
	}
}
