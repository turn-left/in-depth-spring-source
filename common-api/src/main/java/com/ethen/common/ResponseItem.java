package com.ethen.common;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
public class ResponseItem {
    private Instance instance = new Instance();
    private Object result;
    private boolean isSuccess = true;

    @Getter
    @Setter
    @ToString
    public static class Instance {
        private String ip;
        private Integer port;
        private String service;
        private String desc;
    }

    public void buildInstanceInfo(String ip, Integer port, String service, String desc) {
        instance.setIp(ip);
        instance.setPort(port);
        instance.setService(service);
        instance.setDesc(desc);
    }
}
