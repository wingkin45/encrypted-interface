package test;

import com.example.encryptedinterface.utils.RSAUtils;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * @author wingkin
 * @date 2022-12-09 14:32
 */
@Slf4j
public class test {
    public static void main(String[] args) throws Exception {

        Map<String, Object> stringObjectMap = RSAUtils.genKeyPair();
		System.out.println(RSAUtils.getPrivateKey(stringObjectMap));
		System.out.println("------------------------------------");
		System.out.println(RSAUtils.getPublicKey(stringObjectMap));
    }
}
