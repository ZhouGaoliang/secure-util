package com.zgl.util.secure.enums;

public enum EnumCipherAlgorithm {
	DES_ECB_PKCS5Padding(EnumKeyAlgorithm.DES,"DES/ECB/PKCS5Padding"),
	
	DESede_ECB_PKCS5Padding(EnumKeyAlgorithm.DESede,"DESede/ECB/PKCS5Padding"),
	
	AES_ECB_PKCS5Padding(EnumKeyAlgorithm.AES,"AES/ECB/PKCS5Padding"),
	
	IDEA_ECB_PKCS5Padding(EnumKeyAlgorithm.IDEA,"IDEA/ECB/PKCS5Padding"),
	
	RSA_ECB_PKCS1Padding(EnumKeyAlgorithm.RSA,"RSA/ECB/PKCS1Padding"),
	
	ElGamal_ECB_PKCS1Padding(EnumKeyAlgorithm.ElGamal,"ElGamal/ECB/PKCS1Padding"),;
	
	private EnumKeyAlgorithm keyAlgorithm;
	private String value;
	public String getValue() {
		return value;
	}
	private EnumCipherAlgorithm(EnumKeyAlgorithm keyAlgorithm,String value){
		this.keyAlgorithm = keyAlgorithm;
		this.value = value;
	}
	public EnumKeyAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}
}
