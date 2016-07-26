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
	
	
	public static void main(String[] args) throws UnsupportedEncodingException {
		String dataString = "ZGL";
		System.out.println("Base64编码前数据：" + dataString);
		byte[] byteData = dataString.getBytes("utf-8");
		byte[] b = encode(byteData);
		System.out.println("Base64编码后数据：" + new String(b));
	}
	

}
