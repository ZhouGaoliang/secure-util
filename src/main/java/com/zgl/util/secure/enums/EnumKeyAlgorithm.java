package com.zgl.util.secure.enums;

import java.util.ArrayList;
import java.util.List;
/**
 * 密钥算法
 * @author ZGL
 *
 */
public enum EnumKeyAlgorithm {
	/**
	 * 对称加密算法
	 */
	DES,DESede,AES,IDEA,
	/**
	 * 非对称加密算法(RSA,ElGmail常用于非对称加密；RSA,DSA,ECDSA常用于数字签名；)
	 * 说明：
	 * 	1.ECDSA是ECC和DSA的结合
	 * 	2.ECC没有开源组件提供相应支持，Chipher、Signature、KeyPairGenerator、KeyAgreement、SecretKey均不支持ECC算法
	 */  
	RSA,ElGamal,ECC,DSA,ECDSA;
	
	
	public static List<EnumKeyAlgorithm> getSymmetric(){
		List<EnumKeyAlgorithm> keyAlgorithms = new ArrayList<EnumKeyAlgorithm>();
		
		keyAlgorithms.add(EnumKeyAlgorithm.DES);
		keyAlgorithms.add(EnumKeyAlgorithm.DESede);
		keyAlgorithms.add(EnumKeyAlgorithm.AES);
		keyAlgorithms.add(EnumKeyAlgorithm.IDEA);
		return keyAlgorithms;
	}
	
	public static List<EnumKeyAlgorithm> getNonSymmetric(){
		List<EnumKeyAlgorithm> keyAlgorithms = new ArrayList<EnumKeyAlgorithm>();
		
		keyAlgorithms.add(EnumKeyAlgorithm.RSA);
		keyAlgorithms.add(EnumKeyAlgorithm.ElGamal);
		keyAlgorithms.add(EnumKeyAlgorithm.DSA);
		keyAlgorithms.add(EnumKeyAlgorithm.ECC);
		keyAlgorithms.add(EnumKeyAlgorithm.ECDSA);
		return keyAlgorithms;
	
	}
}
