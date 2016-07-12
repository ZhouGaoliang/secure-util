package com.zgl.util.secure.util;

import java.security.InvalidKeyException;
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


import com.zgl.util.secure.enums.EnumSignatureAlgorithm;

/**
 * 数字证书工具类
 * @author ZGL
 *
 */
public class DigitalSignatureUtil {
	
	/**
	 * 私钥签名
	 * @param data
	 * @param privateKey
	 * @return
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 * @throws  
	 * @throws Exception 
	 */
	public static byte[] sign(EnumSignatureAlgorithm signatureAlgorithm,byte[] byteData,byte[] bytePrivateKey) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
		KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getKeyAlgorithm().name());
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		Signature signature = Signature.getInstance(signatureAlgorithm.name());
		signature.initSign(privateKey);
		signature.update(byteData);
		return signature.sign();
	}
	
	/**
	 * 公钥验证签名
	 * @param signatureAlgorithm
	 * @param byteData
	 * @param bytePublicKey
	 * @param byteSign
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 */
	public static boolean verify(EnumSignatureAlgorithm signatureAlgorithm,byte[] byteData,byte[] bytePublicKey,byte[] byteSign) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytePublicKey);
		KeyFactory keyFactory = KeyFactory.getInstance(signatureAlgorithm.getKeyAlgorithm().name());
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		Signature signature = Signature.getInstance(signatureAlgorithm.name());
		signature.initVerify(publicKey);
		signature.update(byteData);
		return signature.verify(byteSign);
	}
	
	public void test() {
		try {
			for (EnumSignatureAlgorithm signatureAlgorithm : EnumSignatureAlgorithm.values()) {
				String dataString = "AAf";
				KeyPair keyPair = KeyUtil.generateKeyPair(signatureAlgorithm.getKeyAlgorithm(), null);
				byte[] byteSign = sign(signatureAlgorithm, dataString.getBytes(), keyPair.getPrivate().getEncoded());
				System.out.println(signatureAlgorithm.name()+ ": " +verify(signatureAlgorithm, dataString.getBytes(), keyPair.getPublic().getEncoded(), byteSign));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		
	}
}
