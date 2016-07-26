package com.zgl.util;
import java.io.Closeable;
import java.io.IOException;


public class IOUtil {
	 public static void close(Closeable... closeables) {
	        if (closeables != null) {
	            for (Closeable closeable : closeables) {
	                if (closeable != null) {
	                    try {
							closeable.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
	                }
	            }
	        }
	    }
}
