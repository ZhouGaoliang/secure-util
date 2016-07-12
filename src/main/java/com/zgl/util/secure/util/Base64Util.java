package com.zgl.util.secure.util;

import java.io.UnsupportedEncodingException;

import org.bouncycastle.util.encoders.Base64;

public class Base64Util {
	public static byte[] encode(byte[] byteData){
		return  Base64.encode(byteData);
	}
	
	public static byte[] decode(byte[] byteData){
		return  Base64.decode(byteData);
	}
	
	public static String encode(String data,String encoding) throws Exception{
		return new String(encode(data.getBytes(encoding)),encoding);
	}
	
	public static String decode(String data,String encoding) throws Exception{
		return new String(encode(data.getBytes(encoding)),encoding);
	}
	
	
	
	
	//@Test
	public void test() throws UnsupportedEncodingException{
		String info = "A";
		byte[] a = info.getBytes("utf-8");
		for (byte c : a) {
			System.out.print(c);
		}
		System.out.println("\n");
		byte[] b = encode(a);
		for (byte c : b) {
			System.out.print(c);
		}
		System.out.println("\n\n");
		System.out.println(new String(b));
		System.out.println(new String(b,"utf-8"));
	}
	
}
