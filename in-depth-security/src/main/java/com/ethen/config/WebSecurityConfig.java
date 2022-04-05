package com.ethen.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * web 安全配置
 * <p>
 * 可选的加密方式参考{@link org.springframework.security.crypto.factory.PasswordEncoderFactories}
 *
 * @author ethen
 * @since 2022/04/05
 */
@Configuration
public class WebSecurityConfig {
    /**
     * bcrypt加密
     *
     * @return BCryptPasswordEncoder
     */
    @Primary
    @Bean
    public PasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 不做加密处理
     *
     * @return NoOpPasswordEncoder
     */
    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder noOpPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

}
