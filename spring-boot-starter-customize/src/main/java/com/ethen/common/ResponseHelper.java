package com.ethen.common;

import org.springframework.core.env.Environment;


public class ResponseHelper {
    public static ResponseItem success(Object data, Environment env) {

        String ip = env.getProperty("spring.cloud.client.ip-address");
        Integer port = env.getProperty("server.port", Integer.class);
        String service = env.getProperty("spring.application.name");
        String desc = env.getProperty("eureka.instance.instance-id");

        ResponseItem responseItem = new ResponseItem();
        responseItem.setResult(data);
        responseItem.buildInstanceInfo(ip, port, service, desc);

        return responseItem;
    }
}

