package test;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.encryptedinterface.utils.HttpUtils;
import com.example.encryptedinterface.utils.InterfaceCipherUtils;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * @author wingkin
 * @date 2022-12-09 16:51
 */
@Slf4j
public class InterfacePostTest {
    public static void main(String[] args) throws Exception {
        String sendText = "这是post接口的数据";
        Map<String, String> encryptedMap = InterfaceCipherUtils.encrypted(sendText,InterfaceCipherUtils.publicKey, InterfaceCipherUtils.aesKey);

        log.info("encryptedMap:{}",JSON.toJSONString(encryptedMap));
        String encryptedMsg= HttpUtils.sendPost("http://localhost:8080/api/test", JSON.toJSONString(encryptedMap));


        String decryptMes=InterfaceCipherUtils.decrypt(JSON.parseObject(encryptedMsg),InterfaceCipherUtils.privateKey);
        log.info("接口返回的消息:{}", decryptMes);
    }


}
