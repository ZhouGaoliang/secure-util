package com.zgl.util.secure.util;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zgl.util.secure.enums.EnumCipherAlgorithm;
import com.zgl.util.secure.enums.EnumKeyAlgorithm;


/**
 * 加解密工具类
 * 
 * @author ZGL
 * 
 */
public class CipherUtil {
	/**
	 * 加密
	 * 
	 * @param byteData
	 *            待加密二进制数据
	 * @param byteKey
	 *            二进制钥匙
	 * @return
	 */
	public static byte[] encrpty(EnumCipherAlgorithm cipherAlgorithm,byte[] byteData, byte[] byteKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		// 生成秘密密钥或公钥
		Key key = null;
		switch (cipherAlgorithm.getKeyAlgorithm()) {
			case DES:
			case DESede:
			case AES:
			case IDEA:
			{
				key = new SecretKeySpec(byteKey, cipherAlgorithm.getKeyAlgorithm().name());
				break;
			}
			case RSA:
			case ElGamal:
			{
				// 获取公钥
				X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
						byteKey);
				key = KeyFactory.getInstance(cipherAlgorithm.getKeyAlgorithm().name())
						.generatePublic(x509EncodedKeySpec);
				break;
			}
			default:
				break;
		}

		Cipher cipher = Cipher.getInstance(cipherAlgorithm.getValue());
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(byteData);
	}

	public static byte[] decrypt(EnumCipherAlgorithm cipherAlgorithm,
			byte[] byteData, byte[] byteKey) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		// 生成秘密密钥或公钥
		Key key = null;
		switch (cipherAlgorithm.getKeyAlgorithm()) {
			case DES:
			case DESede:
			case AES:
			case IDEA:
			{
				key = new SecretKeySpec(byteKey, cipherAlgorithm.getKeyAlgorithm().name());
				break;
			}
			case RSA:
			case ElGamal:
			{
				// 获取私钥
				PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
						byteKey);
				key = KeyFactory.getInstance(cipherAlgorithm.getKeyAlgorithm().name())
						.generatePrivate(pkcs8EncodedKeySpec);
				break;
			}
			default:
				break;
		}

		Cipher cipher = Cipher.getInstance(cipherAlgorithm.getValue());
		cipher.init(Cipher.DECRYPT_MODE, key);
		return cipher.doFinal(byteData);
	}

	//@Test
	public void test() {
		try {
			for (EnumCipherAlgorithm cipherAlgorithm : EnumCipherAlgorithm.values()) {
				String dataString = "AAf";
				if(EnumKeyAlgorithm.getSymmetric().contains(cipherAlgorithm.getKeyAlgorithm())){
					SecretKey secretKey = KeyUtil.generateKey(cipherAlgorithm.getKeyAlgorithm(), null);
					byte[] e = encrpty(cipherAlgorithm, dataString.getBytes(), secretKey.getEncoded());
					byte[] d = decrypt(cipherAlgorithm, e, secretKey.getEncoded());
					System.out.println(cipherAlgorithm.getValue() + ": "+new String(d));
				}else{
					KeyPair keyPair = KeyUtil.generateKeyPair(cipherAlgorithm.getKeyAlgorithm(), null);
					byte[] e = encrpty(cipherAlgorithm, dataString.getBytes(), keyPair.getPublic().getEncoded());
					byte[] d = decrypt(cipherAlgorithm, e, keyPair.getPrivate().getEncoded());
					System.out.println(cipherAlgorithm.getValue()+ ": "+new String(d));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	
		
	}
}
