package com.zgl.util.secure.util;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumSignatureAlgorithm;

/**
 * 数字证书工具类
 * @author ZGL
 *
 */
public class DigitalSignatureUtil {
	/**
	 * 私钥签名
	 * @param signatureAlgorithm 签名算法
	 * @param strHexPrivateKey 16进制字符串私钥
	 * @param byteData
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(EnumSignatureAlgorithm signatureAlgorithm,String strHexPrivateKey,byte[] byteData) throws Exception{
		return sign(signatureAlgorithm, NumberUtil.strHexToBytes(strHexPrivateKey), byteData);
	}
	
	/**
	 * 私钥签名
	 * @param signatureAlgorithm 签名算法
	 * @param bytePrivateKey  二进制私钥
	 * @param byteData 待签名数据
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(EnumSignatureAlgorithm signatureAlgorithm,byte[] bytePrivateKey,byte[] byteData) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
		KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getKeyAlgorithm().name());
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		return sign(signatureAlgorithm, privateKey, byteData);
	}
	
	/**
	 * 私钥签名
	 * @param signatureAlgorithm 签名算法
	 * @param privateKey 私钥
	 * @param byteData 待签名数据
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(EnumSignatureAlgorithm signatureAlgorithm,PrivateKey privateKey,byte[] byteData) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		Signature signature = Signature.getInstance(signatureAlgorithm.name());
		signature.initSign(privateKey);
		signature.update(byteData);
		return signature.sign();
	}
	
	
	
	
	
	
	/**
	 * 公钥校验签名
	 * @param signatureAlgorithm
	 * @param strHexPublicKey 16进制字符串公钥
	 * @param byteData 源数据
	 * @param byteSign 签名
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(EnumSignatureAlgorithm signatureAlgorithm,String strHexPublicKey,byte[] byteData,byte[] byteSign) throws Exception {
		return verify(signatureAlgorithm, NumberUtil.strHexToBytes(strHexPublicKey), byteData, byteSign);
	}

	/**
	 * 公钥校验签名
	 * @param signatureAlgorithm 签名算法
	 * @param bytePublicKey 二进制公钥
	 * @param byteData 源数据
	 * @param byteSign 签名
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static boolean verify(EnumSignatureAlgorithm signatureAlgorithm,byte[] bytePublicKey,byte[] byteData,byte[] byteSign) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytePublicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getKeyAlgorithm().name());
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		return verify(signatureAlgorithm, publicKey, byteData, byteSign);
	}

	/**
	 * 公钥校验签名
	 * @param signatureAlgorithm 签名算法
	 * @param publicKey 公钥
	 * @param byteData 源数据
	 * @param byteSign 签名
	 * @return
	 * @throws Exception
	 */
	public static boolean verify(EnumSignatureAlgorithm signatureAlgorithm,PublicKey publicKey,byte[] byteData,byte[] byteSign) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		Signature signature = Signature.getInstance(signatureAlgorithm.name());
		signature.initVerify(publicKey);
		signature.update(byteData);
		return signature.verify(byteSign);
	}

	
	public static void main(String[] args) throws Exception {
		String dataString = "ZGL";
		for (EnumSignatureAlgorithm signatureAlgorithm : EnumSignatureAlgorithm.values()) {
			System.out.println(signatureAlgorithm.name());
			KeyPair keyPair = KeyUtil.generateKeyPair(signatureAlgorithm.getKeyAlgorithm(), null);
			byte[] byteSign = sign(signatureAlgorithm, NumberUtil.bytesToStrHex(keyPair.getPrivate().getEncoded()), dataString.getBytes());
			System.out.println("签名： " + NumberUtil.bytesToStrHex(byteSign));
			System.out.println("校验结果： "+verify(signatureAlgorithm, keyPair.getPublic().getEncoded(), dataString.getBytes(), byteSign));
			System.out.print("\n");
		}
	}
}
