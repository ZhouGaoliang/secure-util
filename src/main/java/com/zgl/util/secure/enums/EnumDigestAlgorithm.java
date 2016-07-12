package com.zgl.util.secure.enums;

public enum EnumDigestAlgorithm {
	MD2("MD2"),
	MD4("MD4"),
	MD5("MD5"),
	
	
	SHA1("SHA-1"),
	SHA224("SHA-224"),
	SHA256("SHA-256"),
	SHA384("SHA-384"),
	SHA512("SHA-512"),;
	
	private String value;
	public String getValue() {
		return value;
	}
	
	EnumDigestAlgorithm(String value){
		this.value = value;
	}
	
	
	
}
