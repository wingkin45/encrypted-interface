package com.example.encryptedinterface.utils;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * @author wingkin
 * @date 2022/4/20 19:44
 */
@Slf4j
public class InterfaceCipherUtils {
    /**
     * 公钥
     */
    public static String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3HpKzClHSbIGjE9mQNFpUGfTVK4O4tMlWS6zWmJcADhcUGVbP5s89CtU8XHL2TUHTBmOhfFyvD72g7Aj9/fa9KmN4cvRk/iZ44sql4Uj/3LiXDoNpLE6G6/zkNe5F43bLCOu5A/OiyCyvv43uT0ivsXfFZCsARp39HRMMgbJTS6sFVB0flhGy2Vj61vIlbwISrG1hddO32FtNYwLrEPUpsZiUAjVsS9e1nv1ey12b8GbNH3hAIIULWR1o8UwO7aSNPYsOBhaa/davpI0o0K0GFBwt//rpkiAjAVMLUUsp4eCfizBvXERDxb/M9t4kYe77KLXGvhmqXdDSn2CdXFEzwIDAQAB";
    /**
     * 私钥
     */
    public static String privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDcekrMKUdJsgaMT2ZA0WlQZ9NUrg7i0yVZLrNaYlwAOFxQZVs/mzz0K1TxccvZNQdMGY6F8XK8PvaDsCP399r0qY3hy9GT+JnjiyqXhSP/cuJcOg2ksTobr/OQ17kXjdssI67kD86LILK+/je5PSK+xd8VkKwBGnf0dEwyBslNLqwVUHR+WEbLZWPrW8iVvAhKsbWF107fYW01jAusQ9SmxmJQCNWxL17We/V7LXZvwZs0feEAghQtZHWjxTA7tpI09iw4GFpr91q+kjSjQrQYUHC3/+umSICMBUwtRSynh4J+LMG9cREPFv8z23iRh7vsotca+Gapd0NKfYJ1cUTPAgMBAAECggEAAIdXIlpEK/nYO5UVTlDHkSoyt7buPm31Lzppst614Rk4BHxyB2IXNSQo3aZ1Wle4/LhIcytT+NgaZhxwbALLuuibP30/hAh3RuOgDtqCd/7SkIBYneF7NUNX9/yJeWq5sy+nm3HMVSz/hqcf2H1POXayvg8gC6WFTh1im+gZqqfkq3iIDeuRs4P9nXeyiYzwdQNhiPYOXXY1ED3d5Js8zn6rpmlWuUFxOTjO1fNjofiimYTUYN1r+0YdJpvueqRo84W06b5kPxrHk21uxNzEl1X62T+9e5dx1KnndzAYrAxy77uNbkK00CIAbvTQXZ0avOSst5BvdVHijlrhxdNmYQKBgQDuZerE5RUN6UKlDR+V5JLJD0A8i5t8kHr00BNxCbMqBbS3u5MXSsiOzxA82II9ig0EUBa3iLSkJN+e2Cu0oy8FBJwhsLy6syiRh4rkKqkj8slbG9Oeng5+WIlr0jK4uAUbUa1BMAicpzbT6XOFrR/15jepu5tlmpp6MXFD3YH0HwKBgQDswacEelIjYwefl53+GT8TYs3L7FvuXWneS1bWrnrQ9JRL13McN6xxTr7ULdtDeNkBrMySKd+6UX01bdNxAe8VmGIFJjSacuXPsgl3z7Fw2EYqWrdTnHdnsEP6FuIsBZNhoP3/zRRJ4/v3Sk4F/EGNUHDhUt32iUPrKHGUYgQZUQKBgF+v9rB7Bp1j0AUxpEjkyun6vhzPKGSyFTgoQHVxoEEwsx3AI0UJFkED6Y+Sk4wh2iGuB8A5FdCAoGVAfSJvEVNhS03Wg5ooiRMIpX35hZRRQfLY03LqHAUoglgNsaAk9J/Hg9QTdJF0KHScUmsIVzi65AKzs6bvjCuZps3Hnf6fAoGAAVrOUNk+VROA/KnKbqTIVp0PHmaY1BFWxL3bnljbPQzZOGHgN74dz3wq3V3xzj4Hx9msRf3VWOSUedTKC/B95Lq9fNgOHwAfToPvR+85TbL/G8jvGZxglohMq0asPqI9iKZ6LZeH0TBrxat4LNKXsW5PZwqpWHrKl7Lgi3/QFDECgYEAyJdqvV1OAU9y66fCjLG2nJE18Bz77hfhDdbauQPZ7Lki+PHYQ4LRml+l0gcH+Az/YJAN8H45LvQRASmtZfQVew9ZyLYrgx2O0llcz4Hk4xx0yu9aFYd0yKIM0pnFJEDnc6VzdV0RezfuEDijYUqT8CkQACL5TMNK5z7AOwDyfFM=";

    public static String aesKey = "xI/hfVvrfEkp3PnO";
    /**
     * 接口加密数据
     */
    public static Map<String, String> encrypted(String responseData, String publicKey, String aesKey) throws Exception {
        // rsa加密，对aes秘钥进行加密
        String encrypted = RSAUtils.encryptedDataOnJava(aesKey, publicKey);
        // aes加密，对业务报文进行加密
        String requestData = AesEncryptUtils.encrypt(responseData, aesKey);
        Map<String, String> encryptedData = new HashMap<>(16);
        encryptedData.put("aesCiphertext", encrypted);
        encryptedData.put("msg", requestData);
        return encryptedData;
    }

    /**
     * 解密接口接收到的数据
     * @param cipherObj 接收到的密文
     * @param privateKey RSA私钥
     * @return 解密后的数据
     */
    public static String decrypt(JSONObject cipherObj, String privateKey){
        // 密文
        String msg = cipherObj.getString("msg");

        // 加密的aes秘钥
        String aesCiphertext = cipherObj.getString("aesCiphertext");

        if (StringUtils.isEmpty(msg) || StringUtils.isEmpty(aesCiphertext)) {
            throw new RuntimeException("参数【data】缺失异常！");
        } else {
            String content, aseKey;
            try {
                aseKey = RSAUtils.decryptDataOnJava(aesCiphertext, privateKey);
            } catch (Exception e) {
                throw new RuntimeException("参数【aseKey】解析异常！");
            }
            try {
                content = AesEncryptUtils.decrypt(msg, aseKey);
                log.info("请求报文(解密后):{}", content);
            } catch (Exception e) {
                throw new RuntimeException("参数【content】解析异常！");
            }
            if (StringUtils.isEmpty(content) || StringUtils.isEmpty(aseKey)) {
                throw new RuntimeException("参数【data】解析参数空指针异常!");
            }
            return content;
        }
    }

}
