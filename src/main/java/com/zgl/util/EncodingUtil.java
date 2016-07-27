package com.zgl.util;

import com.zgl.util.consts.SecureConst;

public class EncodingUtil {
	public static String getEncoding(String encoding){
		if(encoding == null || "".equals(encoding)){
			return SecureConst.DEFAULT_ENCODING_STRING;
		}
		return encoding;
	}
}
