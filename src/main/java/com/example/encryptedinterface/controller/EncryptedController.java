package com.example.encryptedinterface.controller;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.example.encryptedinterface.utils.InterfaceCipherUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * @author wingkin
 * @date 2022-12-09 15:04
 */

@RestController
@RequestMapping("/api")
@Slf4j
public class EncryptedController {
    @PostMapping("/test")
    public JSONObject getBusinessSystemRoleName(HttpServletRequest request, @RequestBody JSONObject requestObj) throws Exception {
        log.info("接收到的加密消息：{}", requestObj);
        String decryptMessage = InterfaceCipherUtils.decrypt(requestObj, InterfaceCipherUtils.privateKey);
        log.info("解密消息：{}", decryptMessage);

        // 接口返回加密数据
        String result = "收到了，这是返回的消息";
        Map<String, String> responseMap = InterfaceCipherUtils.encrypted(result, InterfaceCipherUtils.publicKey, InterfaceCipherUtils.aesKey);
        log.info("返回消息");

        return JSON.parseObject(JSON.toJSONString(responseMap));

    }
}
