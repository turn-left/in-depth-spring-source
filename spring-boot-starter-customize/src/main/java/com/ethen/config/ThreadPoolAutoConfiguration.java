package com.ethen.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.*;

/**
 * 线程池自动配置
 */
@Configuration
@EnableConfigurationProperties(ThreadPoolProperties.class)
public class ThreadPoolAutoConfiguration {
    @Bean
    @ConditionalOnProperty(prefix = "spring.thread.pool", value = "enabled", havingValue = "true", matchIfMissing = true)
    public ThreadPoolExecutor ioIntensiveThreadPoolExecutor(ThreadPoolProperties properties) {
        ThreadPoolProperties.ThreadPoolParams params = properties.getIoIntensive();
        if (params == null) {
            return null;
        }
        BlockingDeque<Runnable> queue = new LinkedBlockingDeque<>(params.getQueueCapacity());
        ThreadPoolExecutor poolExecutor = new ThreadPoolExecutor(params.getCoreSize(), params.getMaxSize(), params.getKeepAlive(), TimeUnit.MILLISECONDS, queue);
        poolExecutor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        return poolExecutor;
    }
}
