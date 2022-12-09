package com.example.encryptedinterface.utils;

import com.alibaba.fastjson.JSON;
import lombok.extern.slf4j.Slf4j;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.util.Map;

/**
 * @author wingkin
 * @date 2022-12-09 16:58
 */
@Slf4j
public class HttpUtils {

    public static final int SUCCESS_CODE = 200;

    public static String sendPost(String url, String postData) throws Exception{
        //我们可以使用一个Builder来设置UA字段，然后再创建HttpClient对象
        HttpClientBuilder builder = HttpClients.custom();
        //对照UA字串的标准格式理解一下每部分的意思
        builder.setUserAgent("Mozilla/5.0(Windows;U;Windows NT 5.1;en-US;rv:0.9.4)");
        CloseableHttpClient httpClient = builder.build();
        //配置超时时间
        RequestConfig requestConfig = RequestConfig.custom().
                setConnectTimeout(30000).setConnectionRequestTimeout(30000)
                .setSocketTimeout(30000).setRedirectsEnabled(true).build();
        HttpPost httpPost = new HttpPost(url);
        httpPost.setHeader("Content-Type","application/json");
        //设置超时时间
        httpPost.setConfig(requestConfig);
        try {
            StringEntity stringEntity = new StringEntity(postData);
            //设置post请求参数
            httpPost.setEntity(stringEntity);
            HttpResponse httpResponse = httpClient.execute(httpPost);
            String strResult = "";
            if(httpResponse != null){
                System.out.println(httpResponse.getStatusLine().getStatusCode());
                if (httpResponse.getStatusLine().getStatusCode() == SUCCESS_CODE) {
                    strResult = EntityUtils.toString(httpResponse.getEntity());
                } else{
                    log.warn("sendPost请求异常,Error Response: {}",httpResponse.getStatusLine().toString());
                    throw new RuntimeException("sendPost请求异常,Error Response: " + httpResponse.getStatusLine().toString());
                }
            }
            return strResult;
        } finally {
            try {
                if(httpClient != null){
                    httpClient.close(); //释放资源
                }
            } catch (IOException e) {
                log.error("sendPost3连接关闭异常",e);
                throw new IOException("sendPost3连接关闭异常",e);
            }
        }
    }

}
