package com.zgl.util.secure.util;

import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.zgl.util.secure.enums.EnumKeyAlgorithm;



public class KeyUtil {
	public static SecretKey generateKey(EnumKeyAlgorithm keyAlgorithm,Integer keySize) throws NoSuchAlgorithmException{
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm.name());
		switch (keyAlgorithm) {
			case DES:
				keyGen.init(keySize == null ? 56 :keySize); 
				break;
			case DESede:
				keyGen.init(keySize == null ? 168 :keySize); 
				break;
			case AES:
			case IDEA:
				keyGen.init(keySize == null ? 128 :keySize); 
				break;
			default:
				throw new NoSuchAlgorithmException();
		}
		return keyGen.generateKey();
	}
	public static KeyPair generateKeyPair(EnumKeyAlgorithm keyAlgorithm,Integer keySize) throws Exception{
		Security.addProvider(new BouncyCastleProvider());
	
		switch (keyAlgorithm) {
			case RSA:
			case DSA:
			{
				KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyAlgorithm.name());
				keyPairGen.initialize(keySize == null ? 1024 :keySize); 
				return keyPairGen.generateKeyPair(); 
			}
			case ElGamal:
			{
				AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(keyAlgorithm.name());
				apg.init(keySize == null ? 160 :keySize);
				AlgorithmParameters parameters = apg.generateParameters();
				DHParameterSpec elParameterSpec = parameters.getParameterSpec(DHParameterSpec.class);
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm.name());
				keyPairGenerator.initialize(elParameterSpec, new SecureRandom());
				return keyPairGenerator.generateKeyPair();
				
			}
			case ECDSA:	
			{
				BigInteger p = new BigInteger("883432555555365666666666666666666666666666666666666666666666666662");
				ECFieldFp ecFieldFp = new ECFieldFp(p);
				BigInteger a = new BigInteger("7ffffffffffffffffffffffffffffff7ffffffffffffffff80000000007fffffffc", 16);
				BigInteger b = new BigInteger("7fffffffff2352362466577fffffff7657567f80000087976976934537fff233453",16);
				EllipticCurve ellipticCurve = new EllipticCurve(ecFieldFp, a, b);
				BigInteger x = new BigInteger("110243253258329580234023842384592859238592385923895823955235235");
				BigInteger y = new BigInteger("110243253258329423905600223426-92859238592385923895823955235235");
				ECPoint g = new ECPoint(x, y);
				BigInteger n = new BigInteger("594908395929308592804890258920859767623578085934895200818985368340");
				ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, g, n, 1);
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm.name());
				keyPairGenerator.initialize(ecParameterSpec,new SecureRandom());
				return keyPairGenerator.generateKeyPair();
			}
			default:
				throw new NoSuchAlgorithmException();
		}
	
	}

}
