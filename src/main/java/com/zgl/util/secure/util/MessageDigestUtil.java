package com.zgl.util.secure.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumDigestAlgorithm;



/**
 * 消息摘要工具类
 * @author ZGL
 *
 */
public class MessageDigestUtil {
	public static byte[] encode(EnumDigestAlgorithm digestAlgorithm, byte[] byteData) throws NoSuchAlgorithmException{
		Security.addProvider(new BouncyCastleProvider());
		return MessageDigest.getInstance(digestAlgorithm.name()).digest(byteData);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		String dataString = "ZGL";
		for (EnumDigestAlgorithm digestAlgorithm : EnumDigestAlgorithm.values()) {
			byte[] md = encode(digestAlgorithm, dataString.getBytes());
			System.out.println(String.format("%s,摘要信息: %s", digestAlgorithm.getValue(),NumberUtil.bytesToStrHex(md)));
		}
	
	}
}
