package com.zgl.util.secure.enums;

public enum EnumSignatureAlgorithm {
	MD2withRSA(EnumKeyAlgorithm.RSA),
	MD5withRSA(EnumKeyAlgorithm.RSA),
	SHA1withRSA(EnumKeyAlgorithm.RSA),
	SHA224withRSA(EnumKeyAlgorithm.RSA),
	SHA256withRSA(EnumKeyAlgorithm.RSA),
	SHA384withRSA(EnumKeyAlgorithm.RSA),
	SHA512withRSA(EnumKeyAlgorithm.RSA),
	RIPEMD128withRSA(EnumKeyAlgorithm.RSA),
	RIPEMD160withRSA(EnumKeyAlgorithm.RSA),
	
	
	SHA1withDSA(EnumKeyAlgorithm.DSA),
	SHA224withDSA(EnumKeyAlgorithm.DSA),
	SHA256withDSA(EnumKeyAlgorithm.DSA),
	SHA384withDSA(EnumKeyAlgorithm.DSA),
	SHA512withDSA(EnumKeyAlgorithm.DSA),
	
	NONEwithECDSA(EnumKeyAlgorithm.ECDSA),
	SHA1withECDSA(EnumKeyAlgorithm.ECDSA),
	SHA224withECDSA(EnumKeyAlgorithm.ECDSA),
	SHA256withECDSA(EnumKeyAlgorithm.ECDSA),
	SHA384withECDSA(EnumKeyAlgorithm.ECDSA),
	SHA512withECDSA(EnumKeyAlgorithm.ECDSA),
	RIPEMD160withECDSA(EnumKeyAlgorithm.ECDSA);
	
	private EnumKeyAlgorithm keyAlgorithm;
	private EnumSignatureAlgorithm(EnumKeyAlgorithm keyAlgorithm){
		this.keyAlgorithm = keyAlgorithm;
	}
	public EnumKeyAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}

}
