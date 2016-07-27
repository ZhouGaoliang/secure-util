package com.zgl.util.secure.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zgl.util.IOUtil;
import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumKeyStoreType;

/**
 * 密钥库工具
 * @author ZGL
 *
 */
public class KeyStoreUtil {
	private KeyStore keyStore;

	/**
	 * 构造函数
	 * @param keyStoreType 密钥库类型
	 * @param keyStorePath 密钥库路径
	 * @param keyStorePassword 密钥库密码
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public KeyStoreUtil(EnumKeyStoreType keyStoreType, String keyStorePath, String keyStorePassword) throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException{
		this.keyStore = getKeyStoreByPath(keyStoreType, keyStorePath, keyStorePassword);
	}
	
	public KeyStoreUtil(KeyStore keyStore) {
		this.keyStore = keyStore;
	}
	/**
	 * 获取密钥库
	 * @return
	 */
	public KeyStore getKeyStore() {
		return keyStore;
	}
	/**
	 * 获取第一个别名
	 * @param keyStore
	 * @return 
	 * @throws KeyStoreException
	 */
	public String getFirstAlias() throws KeyStoreException{
		Enumeration<String> aliases = keyStore.aliases();
		if(aliases.hasMoreElements()){
			return aliases.nextElement();
		}
		return null;
	}
	/**
	 * 获取私钥
	 * @param alias 别名(可空)
	 * @param keyPassword
	 * @return
	 * @throws UnrecoverableKeyException
	 * @throws KeyStoreException
	 * @throws NoSuchAlgorithmException
	 */
	public PrivateKey getPrivateKey(String alias,String keyPassword) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException{
		if(alias == null){
			alias = getFirstAlias();
		}
		return (PrivateKey) keyStore.getKey(alias, keyPassword.toCharArray());
	}
	
	public Certificate getCertificate(String alias) throws KeyStoreException{
		if(alias == null){
			alias = getFirstAlias();
		}
		return keyStore.getCertificate(alias);
	}
	
	/**
	 * 获取公钥
	 * @param alias alias 别名(可空)
	 * @return
	 * @throws KeyStoreException
	 */
	public PublicKey getPublicKey(String alias) throws KeyStoreException{
		Certificate certificate = getCertificate(alias);
		return certificate.getPublicKey();
	}
	
	
	
	/**
	 * 密钥库中的公钥加密
	 * @param keyStoreType 密钥库类型
	 * @param keyStorePath 密钥库路径
	 * @param keyStorePassword 密码
	 * @param alias 别名（可空）
	 * @param byteData 待加密数据
	 * @return 加密数据
	 * @throws KeyStoreException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws Exception
	 */
	public byte[] encrptyByPublicKey(String alias, byte[] byteData) 
			throws KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		PublicKey publicKey = getPublicKey(alias);
		return CipherUtil.encrpty(null, publicKey, byteData);
	}
	
	/**
	 * 密钥库中的私钥加密
	 * @param alias 别名（可空）
	 * @param keyPassword 钥匙密码
	 * @param byteData 待加密数据
	 * @return 加密数据
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws Exception
	 */
	public byte[] encrptyByPrivateKey(String alias,String keyPassword, byte[] byteData) 
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		PrivateKey privateKey = getPrivateKey(alias,keyPassword);
		return CipherUtil.encrpty(null, privateKey, byteData);
	}
	

	/**
	 * 密钥库中的公钥解密
	 * @param alias 别名（可空）
	 * @param byteData 待解密数据
	 * @return
	 * @throws KeyStoreException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws Exception
	 */
	public byte[] decryptByPublicKey(String alias, byte[] byteData) 
			throws KeyStoreException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		PublicKey publicKey = getPublicKey(alias);
		return CipherUtil.decrypt(null, publicKey, byteData);
	}
	
	/**
	 * 密钥库中的私钥解密
	 * @param keyStoreType 密钥库类型
	 * @param keyStorePath 密钥库路径
	 * @param keyStorePassword 密码
	 * @param alias 别名(可空)
	 * @param byteData 待解密数据
	 * @return
	 * @throws NoSuchAlgorithmException 
	 * @throws KeyStoreException 
	 * @throws UnrecoverableKeyException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws InvalidKeyException 
	 * @throws Exception
	 */
	public byte[] decryptByPrivateKey(String alias,String keyPassword, byte[] byteData) 
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		PrivateKey privateKey = getPrivateKey(alias, keyPassword);
		return CipherUtil.decrypt(null, privateKey, byteData);
	}
	
	/**
	 * 密钥库中的私钥签名
	 * @param alias 别名(可空)
	 * @param keyPassword 钥匙密码
	 * @param byteData 待签名数据
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws IOException
	 * @throws UnrecoverableKeyException
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 */
	public byte[] sign(String alias,String keyPassword, byte[] byteData) 
			throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableKeyException, InvalidKeyException, SignatureException{
		PrivateKey privateKey = getPrivateKey(alias, keyPassword);
		X509Certificate x509Certificate= (X509Certificate) getCertificate(alias);
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		signature.initSign(privateKey);
		signature.update(byteData);
		return signature.sign();
	}
	
	/**
	 * 密钥库中的公钥校验签名
	 * @param alias 别名(可空)
	 * @param byteData 源数据
	 * @param byteSign 二进制签名
	 * @return 校验结果
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws SignatureException
	 * @throws InvalidKeyException
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public boolean verify(String alias, byte[] byteData,byte[] byteSign) 
			throws NoSuchAlgorithmException, CertificateException, SignatureException, InvalidKeyException, KeyStoreException, IOException {
		X509Certificate x509Certificate= (X509Certificate) getCertificate(alias);
		return new CertificateUtil(x509Certificate).verify(byteData, byteSign);
	}
	
	
	
	/**
	 * 获取密钥库
	 * @param keyStoreType 密钥库类型
	 * @param keyStorePath 密钥库路径
	 * @param keyStorePassword 密钥库密码
	 * @return 密钥库
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 * @throws IOException
	 */
	public static KeyStore getKeyStoreByPath(EnumKeyStoreType keyStoreType,String keyStorePath,String keyStorePassword) 
			throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException{
		FileInputStream fis = new FileInputStream(keyStorePath);
		return getKeyStoreByInputStream(keyStoreType,fis, keyStorePassword);
	}
	
	
	/**
	 * 
	 * @param keyStoreType 密钥库类型
	 * @param is 输入流
	 * @param keyStorePassword 密钥库密码
	 * @return 密钥库
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public static KeyStore getKeyStoreByInputStream(EnumKeyStoreType keyStoreType,InputStream is,String keyStorePassword) 
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException{
		Security.addProvider(new BouncyCastleProvider());
		if(keyStoreType == null){
			keyStoreType = EnumKeyStoreType.JKS;
		}
		KeyStore ks = KeyStore.getInstance(keyStoreType.getValue());
		ks.load(is, keyStorePassword.toCharArray());
		IOUtil.close(is);
		return ks;
	}
	
	public static void main(String[] args) throws Exception {
		String classpath = KeyStoreUtil.class.getResource("/").toString().replace("file:/", "");
		String keyStorePath = String.format("%s%s", classpath,"test.pfx");
		String keyStorePassword = "000000";
		String keyPassword = "000000";
		
		KeyStoreUtil keyStoreUtil = new KeyStoreUtil(EnumKeyStoreType.PKCS12, keyStorePath, keyStorePassword);
		String dataString = "ZGL";
		
		System.out.println("公钥加密，私钥解密");
		byte[] e = keyStoreUtil.encrptyByPublicKey(null, dataString.getBytes());
		System.out.println("公钥加密后数据："+ NumberUtil.bytesToStrHex(e));
		byte[] d = keyStoreUtil.decryptByPrivateKey(null, keyPassword, e);
		System.out.println("私钥解密后数据: "+ new String(d));
		System.out.print("\n");
		
		
		System.out.println("私钥加密，公钥解密");
		e = keyStoreUtil.encrptyByPrivateKey(null, keyPassword,  dataString.getBytes());
		System.out.println("私钥加密后数据："+  NumberUtil.bytesToStrHex(e));
		d = keyStoreUtil.decryptByPublicKey(null, e);
		System.out.println("公钥解密后数据: "+ new String(d));
		System.out.print("\n");
		
		
		System.out.println("私钥签名，公钥校验签名");
		byte[] s = keyStoreUtil.sign(null, keyPassword, dataString.getBytes());
		System.out.println("私钥签名后数据："+ NumberUtil.bytesToStrHex(s));
		System.out.println("公钥校验结果：" + keyStoreUtil.verify(null, dataString.getBytes(), s));
	}

}
