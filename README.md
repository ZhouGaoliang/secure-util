# secure-util
##简介
Base64编码，消息摘要，对称(DES,3DES,AES,IDEA)/非对称(RSA,ELGamal)加解密，RSA/DSA数字签名，数字证书(待完善)工具类

##版本信息
V1.0 初始版本发布

##升级计划
即将发布1.1版本，更新内容：
支持数字证书

##注意
Java几乎各种常用加密算法都能找到对应的实现。因为美国的出口限制，Sun通过权限文件（local_policy.jar、US_export_policy.jar）做了相应限制。因此存在一些问题：
●密钥长度上不能满足需求（如：java.security.InvalidKeyException: Illegal key size or default parameters）；
●部分算法未能支持，如MD4、SHA-224等算法；
●API使用起来还不是很方便；一些常用的进制转换辅助工具未能提供，如Base64编码转换、十六进制编码转换等工具。
Oracle在其官方网站上提供了无政策限制权限文件（Unlimited Strength Jurisdiction Policy Files），我们只需要将其部署在JRE环境中，就可以解决限制问题。

Java 6 无政策限制文件：
http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html
Java 7 无政策限制文件：
http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html