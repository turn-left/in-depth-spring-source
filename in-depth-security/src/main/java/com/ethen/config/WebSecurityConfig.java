//package com.ethen.config;
//
//import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.context.annotation.Primary;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
///**
// * web 安全配置
// * <p>
// * 可选的加密方式参考{@link org.springframework.security.crypto.factory.PasswordEncoderFactories}
// *
// * @author ethen
// * @since 2022/04/05
// */
//@Configuration
//public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
//    /**
//     * bcrypt加密
//     *
//     * @return BCryptPasswordEncoder
//     */
//    @Primary
//    @Bean
//    public PasswordEncoder bCryptPasswordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    /**
//     * 不做加密处理
//     *
//     * @return NoOpPasswordEncoder
//     */
//    @Bean
//    @ConditionalOnMissingBean(PasswordEncoder.class)
//    public PasswordEncoder noOpPasswordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
//    }
//
//    /**
//     * 配置http安全选项
//     *
//     * <ol>
//     *     <li>静态资源拦截策略</li>
//     *     <li>接口拦截策略</li>
//     *     <li>CSRF安全策略</li>
//     *     <li>登入/登出选项</li>
//     * </ol>
//     *
//     * @param http HttpSecurity
//     * @throws Exception
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        // 表单提交
//        http.formLogin()
//                // 自定义登录页
////                .loginPage("login.html")
//                // 登录接口路径，须与表单提交一致
////                .loginProcessingUrl("/user/login")
//                // 认证成功跳转路径
//                .defaultSuccessUrl("/index.html")
//                .and().authorizeRequests()
//                // 设置不需要认证的路径
//                .antMatchers("/user/login", "/login.html").permitAll()
//                .antMatchers("/**/hello/**").permitAll()
//                // 设置需要认证的路径
//                .anyRequest().authenticated();
//
//        // 关闭CSRF校验
//        http.csrf().disable();
//    }
//}
