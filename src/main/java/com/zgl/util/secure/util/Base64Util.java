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
	
	public static String encode(String data,String encoding) throws UnsupportedEncodingException{
		return new String(encode(data.getBytes(encoding)),encoding);
	}
	
	public static String decode(String data,String encoding) throws UnsupportedEncodingException{
		return new String(decode(data.getBytes(encoding)),encoding);
	}
	
	public static byte[] encode2Bytes(String data,String encoding) throws UnsupportedEncodingException{
		return encode(data.getBytes(encoding));
	}
	
	public static byte[] decode2Bytes(String data,String encoding) throws UnsupportedEncodingException{
		return decode(data.getBytes(encoding));
	}
	
	public static String encode2Str(byte[] byteData, String encoding) throws UnsupportedEncodingException{
		return  new String(encode(byteData),encoding);
	}
	
	public static String decode2Str(byte[] byteData,String encoding) throws UnsupportedEncodingException{
		return new String(decode(byteData),encoding);
	}
	
	
	public static void main(String[] args) throws Exception {
		String dataString = "ZGL";
		System.out.println("Base64编码前数据：" + dataString);
		String e = encode(dataString, "utf-8");
		System.out.println("Base64编码后数据：" + e);
		System.out.println("Base64解码后数据：" + decode(e, "utf-8"));
	}
	

}
