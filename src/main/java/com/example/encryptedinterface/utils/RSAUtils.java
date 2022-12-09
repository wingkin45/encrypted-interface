package com.example.encryptedinterface.utils;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/** */

/**
 * <p>
 * RSA公钥/私钥/签名工具包
 * </p>
 * <p>
 * 罗纳德·李维斯特（Ron [R]ivest）、阿迪·萨莫尔（Adi [S]hamir）和伦纳德·阿德曼（Leonard [A]dleman）
 * </p>
 * <p>
 * 字符串格式的密钥在未在特殊说明情况下都为BASE64编码格式<br/>
 * 由于非对称加密速度极其缓慢，一般文件不使用它来加密而是使用对称加密，<br/>
 * 非对称加密算法可以用来对对称加密的密钥加密，这样保证密钥的安全也就保证了数据的安全
 * </p>
 * 
 * @author monkey
 * @date 2018-10-29
 */
public class RSAUtils {

	/**
	 * 加密算法RSA
	 */
	public static final String KEY_ALGORITHM = "RSA";

	/**
	 * 签名算法
	 */
	public static final String SIGNATURE_ALGORITHM = "MD5withRSA";

	/**
	 * 获取公钥的key
	 */
	private static final String PUBLIC_KEY = "RSAPublicKey";

	/**
	 * 获取私钥的key
	 */
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * RSA最大加密明文大小
	 */
	private static final int MAX_ENCRYPT_BLOCK = 245;

	/**
	 * RSA最大解密密文大小
	 */
	private static final int MAX_DECRYPT_BLOCK = 256;

	/**
	 * RSA 位数 如果采用2048 上面最大加密和最大解密则须填写:  245 256
	 */
	private static final int INITIALIZE_LENGTH = 2048;

	/**
	 * 生成密钥对(公钥和私钥)
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> genKeyPair() throws Exception {
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
		keyPairGen.initialize(INITIALIZE_LENGTH);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>(2);
		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}

	/**
	 * 用私钥对信息生成数字签名
	 * @param data 已加密数据
	 * @param privateKey 私钥(BASE64编码)
	 * 
	 * @return
	 * @throws Exception
	 */
	public static String sign(byte[] data, String privateKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(privateK);
		signature.update(data);
		return Base64.encodeBase64String(signature.sign());
	}

	/**
	 * 校验数字签名
	 * @param data 已加密数据
	 * @param publicKey 公钥(BASE64编码)
	 * @param sign 数字签名
	 * 
	 * @return
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		PublicKey publicK = keyFactory.generatePublic(keySpec);
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(publicK);
		signature.update(data);
		return signature.verify(Base64.decodeBase64(sign));
	}

	/**
	 * 私钥解密
	 * @param encryptedData 已加密数据
	 * @param privateKey 私钥(BASE64编码)
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privateK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	/**
	 * 公钥解密
	 * @param encryptedData 已加密数据
	 * @param publicKey 公钥(BASE64编码)
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicK);
		int inputLen = encryptedData.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段解密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_DECRYPT_BLOCK) {
				cache = cipher.doFinal(encryptedData, offSet, MAX_DECRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_DECRYPT_BLOCK;
		}
		byte[] decryptedData = out.toByteArray();
		out.close();
		return decryptedData;
	}

	/**
	 * 公钥加密
	 * @param data 源数据
	 * @param publicKey 公钥(BASE64编码)
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(publicKey);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key publicK = keyFactory.generatePublic(x509KeySpec);
		// 对数据加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, publicK);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	/**
	 * 私钥加密
	 * @param data 源数据
	 * @param privateKey 私钥(BASE64编码)
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws Exception {
		byte[] keyBytes = Base64.decodeBase64(privateKey);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
		Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privateK);
		int inputLen = data.length;
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		int offSet = 0;
		byte[] cache;
		int i = 0;
		// 对数据分段加密
		while (inputLen - offSet > 0) {
			if (inputLen - offSet > MAX_ENCRYPT_BLOCK) {
				cache = cipher.doFinal(data, offSet, MAX_ENCRYPT_BLOCK);
			} else {
				cache = cipher.doFinal(data, offSet, inputLen - offSet);
			}
			out.write(cache, 0, cache.length);
			i++;
			offSet = i * MAX_ENCRYPT_BLOCK;
		}
		byte[] encryptedData = out.toByteArray();
		out.close();
		return encryptedData;
	}

	/**
	 * 获取私钥
	 * @param keyMap 密钥对
	 * @return
	 * @throws Exception
	 */
	public static String getPrivateKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PRIVATE_KEY);
		return Base64.encodeBase64String(key.getEncoded());
	}

	/**
	 * 获取公钥
	 * @param keyMap 密钥对
	 * @return
	 * @throws Exception
	 */
	public static String getPublicKey(Map<String, Object> keyMap) throws Exception {
		Key key = (Key) keyMap.get(PUBLIC_KEY);
		return Base64.encodeBase64String(key.getEncoded());
	}

	/**
	 * java端公钥加密
	 */
	public static String encryptedDataOnJava(String data, String PUBLICKEY) {
		try {
			data = Base64.encodeBase64String(encryptByPublicKey(data.getBytes(), PUBLICKEY));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return data;
	}

	/**
	 * java端私钥解密
	 */
	public static String decryptDataOnJava(String data, String privateKey) {
		String temp = "";
		try {
			byte[] rs = Base64.decodeBase64(data);
			temp = new String(RSAUtils.decryptByPrivateKey(rs, privateKey), StandardCharsets.UTF_8);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return temp;
	}

	/**
	 * 创建指定位数的随机字符串
	 * @param length 表示生成字符串的长度
	 * @return 字符串
	 */
	public static String getRandomString(int length) {
		String base = "abcdefghijklmnopqrstuvwxyz0123456789";
		Random random = new Random();
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < length; i++) {
			int number = random.nextInt(base.length());
			sb.append(base.charAt(number));
		}
		return sb.toString();
	}

	public static void main(String[] args) throws  Exception{
//		Map<String, Object> stringObjectMap = RSAUtils.genKeyPair();
//		System.out.println(getPrivateKey(stringObjectMap));
//		System.out.println("------------------------------------");
//		System.out.println(getPublicKey(stringObjectMap));

		String privateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCmp1lwiIYSQ1ojcgieI9kptFk//TcIlhqO3YI0RoWrJfZFaajeqdekR7Hs0mWtNjsXihVcgsTyhQfI0NCT37yS7W8zKb48oHTsCyVztbZfmFYEnf00EQorzGSAkM99TH5Iwsg+AnCactQ3AO1eqjT5pkq3GbEmBZoPSqqOHtFMA/ygvDWXfWVt2qi64b89I8rIctNbyDi1MKQsu2MrEeaFuCyn9S7JXAZVTQZ1VpJV3NJbZn9j8pki7hV9FSFEqfFEX+8bdx3BW/sv4saEnWdPiVLPRhv504jYhK5Uqz7ZwBnAe3jN6iaN3OmqYSpFKrVf92M3yc1jR2gEo5qz253bAgMBAAECggEAWaMVllO4WUZkyz/gpr59ZdMdVi+qVDH4YvN9vwRXjTDD/53POMR9ulzdtJWOHtZWfljFGJc1u4QWJcs7BO6IjTasYwaGzjE38mYkZNJOH6jeS2l28XRg1iH/xK8fCzQDkLtD3SaOzmQJBPS4t/wwtj7dXRKyl9LXhHYSupKU3J8+rYBxhapc6hH8MeEDmJypkhTajGTxGQPlA1F6SFO+fAicnX0ic4K/ciXosIYJY0eEmaCjxtmmi6h+7zKohxfEAcJDO49JYJtC7RZdRIHvIx5ylo11o2DZuil/61RhF3nsXzyCuGLqvuvfJNhLNr4xj97cpESMF0zGtIA8Zm87sQKBgQD2bpnrkuxV6oMZFLId/2TyBUWnh4uiOnxJ3iO4b1xRXlVbAJK7z0GvZh0F3thKqtjYlY8b4TAmksPhYIE0JzvE7mczgEMCYbXoCSw2WomshBXY1UUSc7QuH677Ab4/WB4Ni5/CnhjIN+aO5X9tBaaJoukefHOp66LQ9S4tRvuDLwKBgQCtH8ukIQk/0ci422km5r1sBjDe1qMQal8Ty3G7Ihg2/bTSRxY5KdoPb8fLjfn5VzNitNLj7a5SDA3VEDwVBDaQbgmLnhcYE8fryVLct+c6aqzaBZ+h4hrJGnJ7F6IemuYY+tquQ6WY1BOuAXCa3/Y3sSRt/RTrY1wnnd4lFjkVFQKBgEA0ks/IyOCdqCh5tuqP5woTi5FZhGzxFf7c7KuaABCHJm/+VzythCyhy0ADTpEtsC/Fz7Jw2m3CYVywGxmueykVADhv24WcVZuuACHtNt+GznZfIo7rLG+z+5AUZS/10mavESHQtR49SknCy49pIHnNwzUZMb180j/lEXHkg5UrAoGASDw5Cv2hz1goCUG7aTjjlnwqzf/+v+2ySB8eEDfUpLVNSmPQ2P8mdkRst/lAcRI6ZZgPWn0kvCU9bEY+24ILhk3ze6b1+dzfEPnKsj+lolE6WCn6hmBCTuDTHZsp0N1O3uNkdUvSf6cVowgExQpnwKsQCTiNDv5BSGJte0n/fVUCgYAKlFUZJGKdMN1SON5+b7pwa/7U5xL/uWc4Otqx+6LGLf+LPOFG3Z9LRN+ai/fGwUuYp0pneDCejIasEiuIiXmweT/Gb7FXmgD3X6Lx765DGv418Vu7nJTkQq1HKja1S2NFurpDDOKYFSp5bcszAQNUgBKNYFuU92VBg2dtsAdtEg==";
		String publicKey="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApqdZcIiGEkNaI3IIniPZKbRZP/03CJYajt2CNEaFqyX2RWmo3qnXpEex7NJlrTY7F4oVXILE8oUHyNDQk9+8ku1vMym+PKB07Aslc7W2X5hWBJ39NBEKK8xkgJDPfUx+SMLIPgJwmnLUNwDtXqo0+aZKtxmxJgWaD0qqjh7RTAP8oLw1l31lbdqouuG/PSPKyHLTW8g4tTCkLLtjKxHmhbgsp/UuyVwGVU0GdVaSVdzSW2Z/Y/KZIu4VfRUhRKnxRF/vG3cdwVv7L+LGhJ1nT4lSz0Yb+dOI2ISuVKs+2cAZwHt4zeomjdzpqmEqRSq1X/djN8nNY0doBKOas9ud2wIDAQAB";
		String data = encryptedDataOnJava("System.out.println(getPrivateKey(stringObjectMap))", publicKey);
		String java = decryptDataOnJava(data, privateKey);
		System.out.println(java);
	}
}