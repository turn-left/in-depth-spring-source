package com.ethen.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "spring.thread.pool")
public class ThreadPoolProperties {
    /**
     * IO密集型线程池
     */
    private ThreadPoolParams ioIntensive;
    /**
     * CPU密集型线程池
     */
    private ThreadPoolParams cpuIntensive;

    /**
     * 配置参数
     */
    @Getter
    @Setter
    @ToString
    public static class ThreadPoolParams {
        private int coreSize;
        private int maxSize;
        private int queueCapacity;
        private long keepAlive;
    }
}
