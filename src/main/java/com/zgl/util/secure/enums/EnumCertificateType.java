package com.zgl.util.secure.enums;

public enum EnumCertificateType {
	X509("X.509");
	
	
	private String value;
	public String getValue() {
		return value;
	}
	private EnumCertificateType(String value){
		this.value = value;
	}
}
