package com.zgl.util.secure.util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zgl.util.IOUtil;
import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumCertificateType;
import com.zgl.util.secure.enums.EnumKeyStoreType;
/**
 * 证书工具
 * @author ZGL
 *
 */
public class CertificateUtil {
	private Certificate certificate;


	/**
	 * 构造函数
	 * @param certificateType 证书类型
	 * @param certficatePath 证书路径
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 */
	public CertificateUtil(EnumCertificateType certificateType,String certficatePath) throws FileNotFoundException, CertificateException{
		this.certificate = getCertificateByPath(certificateType,certficatePath);
	}
	
	public CertificateUtil(Certificate certificate){
		this.certificate = certificate;
	}
	
	
	/**
	 * 证书所含公钥加密
	 * @param certficateType 证书类型
	 * @param certficatePath 证书路径
	 * @param byteData 待加密数据
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws Exception
	 */
	public  byte[] encrptyByPublicKey(byte[] byteData) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		PublicKey publicKey = this.certificate.getPublicKey();
		return CipherUtil.encrpty(null, publicKey, byteData);
	}
	
	
	/**
	 * 证书所含公钥解密
	 * @param certficateType 证书类型
	 * @param certficatePath 证书路径
	 * @param byteData 待解密数据
	 * @return
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws Exception
	 */
	public byte[] decryptByPublicKey(byte[] byteData) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		PublicKey publicKey = this.certificate.getPublicKey();
		return CipherUtil.decrypt(null, publicKey, byteData);
	}
	
	/**
	 * 证书所含公钥校验签名
	 * @param certficateType 证书类型
	 * @param certficatePath 证书路径
	 * @param byteData 源数据
	 * @param byteSign 签名
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateException 
	 * @throws FileNotFoundException 
	 * @throws SignatureException 
	 * @throws InvalidKeyException 
	 */
	public boolean verify(byte[] byteData,byte[] byteSign) throws NoSuchAlgorithmException, FileNotFoundException, CertificateException, SignatureException, InvalidKeyException {
		X509Certificate x509Certificate = (X509Certificate) this.certificate;
		Signature signature = Signature.getInstance(x509Certificate.getSigAlgName());
		signature.initVerify(x509Certificate);
		signature.update(byteData);
		return signature.verify(byteSign);
	}
	
	/**
	 * 获取证书
	 * @return
	 */
	public Certificate getCertificate() {
		return certificate;
	}

	
	/**
	 * 获取证书
	 * @param certificateType 证书类型
	 * @param certficatePath 证书路径
	 * @return 证书
	 * @throws FileNotFoundException
	 * @throws CertificateException
	 */
	public static Certificate getCertificateByPath(EnumCertificateType certificateType,String certficatePath) throws FileNotFoundException, CertificateException{
		FileInputStream fis = new FileInputStream(certficatePath);
		return getCertificateByInputStream(certificateType,fis);
	}
	/**
	 * 获取证书
	 * @param certificateType 证书类型
	 * @param is 输入流
	 * @return 证书
	 * @throws CertificateException
	 */
	public static Certificate getCertificateByInputStream(EnumCertificateType certificateType,InputStream is) throws CertificateException{
		Security.addProvider(new BouncyCastleProvider());
		if(certificateType == null){
			certificateType = EnumCertificateType.X509;
		}
		CertificateFactory certificateFactory = CertificateFactory.getInstance(certificateType.getValue());
		Certificate certificate = certificateFactory.generateCertificate(is);
		IOUtil.close(is);
		return certificate;
	}
	
	public static void main(String[] args) throws Exception {
		String classpath = KeyStoreUtil.class.getResource("/").toString().replace("file:/", "");
		String certificatePath = String.format("%s%s", classpath,"test.cer");
		String keyStorePath = String.format("%s%s", classpath,"test.pfx");
		String keyStorePassword = "000000";
		String keyPassword = "000000";
		
		CertificateUtil certificateUtil = new CertificateUtil(EnumCertificateType.X509, certificatePath);
		KeyStoreUtil keyStoreUtil = new KeyStoreUtil(EnumKeyStoreType.PKCS12, keyStorePath, keyStorePassword);
		String dataString = "ZGL";

		System.out.println("公钥加密，私钥解密");
		byte[] e = certificateUtil.encrptyByPublicKey(dataString.getBytes());
		System.out.println("公钥加密后数据："+ NumberUtil.bytesToStrHex(e));
		byte[] d = keyStoreUtil.decryptByPrivateKey(null, keyPassword, e);
		System.out.println("私钥解密后数据: "+ new String(d));
		System.out.print("\n");
		
		
		System.out.println("私钥加密，公钥解密");
		e = keyStoreUtil.encrptyByPrivateKey(null, keyPassword,  dataString.getBytes());
		System.out.println("私钥加密后数据："+  NumberUtil.bytesToStrHex(e));
		d = certificateUtil.decryptByPublicKey(e);
		System.out.println("公钥解密后数据: "+ new String(d));
		System.out.print("\n");
		
		System.out.println("私钥签名，公钥校验签名");
		byte[] s = keyStoreUtil.sign(null, keyPassword, dataString.getBytes());
		System.out.println("私钥签名后数据："+ NumberUtil.bytesToStrHex(s));
		System.out.println("公钥校验结果：" + certificateUtil.verify( dataString.getBytes(), s));
		
		
	}

}
