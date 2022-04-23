package com.ethen.common;

import org.springframework.core.env.Environment;

import java.util.Objects;

/**
 * ResponseHelper
 */
public class ResponseHelper {

    public static ResponseItem success(Object data, Environment env) {
        ResponseItem responseItem = new ResponseItem();
        responseItem.setResult(data);
        if (Objects.nonNull(env)) {
            String ip = env.getProperty("spring.cloud.client.ip-address");
            Integer port = env.getProperty("server.port", Integer.class);
            String service = env.getProperty("spring.application.name");
            String desc = env.getProperty("eureka.instance.instance-id");
            responseItem.buildInstanceInfo(ip, port, service, desc);
        }
        return responseItem;
    }

    public static ResponseItem success(Object data) {
        return success(data, null);
    }
}

