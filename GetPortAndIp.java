package com.nari.osp.pascloud;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;

public class GetPortAndIp {
	//获取Ip 
	public static String getLocalIP(HttpServletRequest request) throws UnknownHostException, SocketException {
        if (isWindowsOS()) {
            return getIpAddress(request);
        } else {
            return getLinuxLocalIp();
        }
    }

	/**
     * 获取端口号
     * */
    public static int getPortAddress(HttpServletRequest request){
    	int port = 0;
    	port = request.getServerPort();
    	return port;
    }
    
    /**
     * 判断操作系统是否是Windows
     *
     * @return
     */
    public static boolean isWindowsOS() {
        boolean isWindowsOS = false;
        String osName = System.getProperty("os.name");
        if (osName.toLowerCase().indexOf("windows") > -1) {
            isWindowsOS = true;
        }
        return isWindowsOS;
    }
    
    /**
     * 获取本地Host名称
     */
    public static String getLocalHostName() throws UnknownHostException {
        return InetAddress.getLocalHost().getHostName();
    }
    
    /**
     * 获取Linux下的IP地址
     *
     * @return IP地址
     * @throws SocketException
     */
    private static String getLinuxLocalIp() throws SocketException {
        String ip = "";
        try {
            for (Enumeration<NetworkInterface> en = NetworkInterface.getNetworkInterfaces(); en.hasMoreElements();) {
                NetworkInterface intf = en.nextElement();
                String name = intf.getName();
                if (!name.contains("docker") && !name.contains("lo")) {
                    for (Enumeration<InetAddress> enumIpAddr = intf.getInetAddresses(); enumIpAddr.hasMoreElements();) {
                        InetAddress inetAddress = enumIpAddr.nextElement();
                        if (!inetAddress.isLoopbackAddress()) {
                            String ipaddress = inetAddress.getHostAddress().toString();
                            if (!ipaddress.contains("::") && !ipaddress.contains("0:0:") && !ipaddress.contains("fe80")) {
                                ip = ipaddress;
                                System.out.println(ipaddress);
                            }
                        }
                    }
                }
            }
        } catch (SocketException ex) {
            System.out.println("获取ip地址异常");
            ip = "127.0.0.1";
            ex.printStackTrace();
        }
        System.out.println("IP:linux;;;;;;;;;;;;;="+ip);
        return ip;
    }
    /**
     * 获取Wndows下的IP地址
     *当我们通过request获取客户端IP时，自身服务器通常会为了保护信息或者负载均衡的目的，对自身服务器做反向代理。
     *此时如果我们通过request.getRemoteAddr();可能获取到的是自身代理服务器的IP，而无法达到获取用户请求ip的目的。
     * @return IP地址
     */
    public static String getIpAddress(HttpServletRequest request) {
    	//X-Forwarded-For：Squid 服务代理
        String ip = request.getHeader("X-Forwarded-For");
        //Proxy-Client-IP：apache 服务代理
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        //WL-Proxy-Client-IP：weblogic 服务代理
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        //HTTP_CLIENT_IP：有些代理服务器
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        //X-Real-IP：nginx服务代理
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        //有些网络通过多层代理，那么获取到的ip就会有多个，一般都是通过逗号（,）分割开来，并且第一个ip为客户端的真实IP
        if (ip != null && ip.length() != 0) {
            ip = ip.split(",")[0];
        }
       //还是不能获取到，最后再通过request.getRemoteAddr();获取
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        ip = ip.equals("0:0:0:0:0:0:0:1")?"127.0.0.1":ip;
        System.out.println("IP:windows;;;;;;;;;;;;;="+ip);
        return ip;
    }
}
