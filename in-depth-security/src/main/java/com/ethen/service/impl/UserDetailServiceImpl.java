package com.ethen.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 自定义 spring security UserDetailsService 实现
 * <p>
 * fixme 待分析spring security调用链路源码
 * <p>
 * note: spring boot 自动配置(spring-boot-autoconfigure)默认是
 * {@link org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration},
 * 如果不存在自定义实现，默认就是配置内存用户密码权限。
 *
 * @author ethen
 * @since 2022/04/05
 */
@Service
public class UserDetailServiceImpl implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Locates the user based on the username. In the actual implementation, the search
     * may possibly be case sensitive, or case insensitive depending on how the
     * implementation instance is configured. In this case, the <code>UserDetails</code>
     * object that comes back may have a username that is of a different case than what
     * was actually requested..
     *
     * @param username the username identifying the user whose data is required.
     * @return a fully populated user record (never <code>null</code>)
     * @throws UsernameNotFoundException if the user could not be found or the user has no
     *                                   GrantedAuthority
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // V1.0维护一个内存的用户密码权限，实际通常从数据库获取用户权限数据
        String rawPwd = "root123";

        String encodedPwd = passwordEncoder.encode(rawPwd);

        System.err.println("encodedPwd:" + encodedPwd);

        UserDetails userDetails = User.withUsername("ethen").password(encodedPwd).authorities("admin").build();

        return userDetails;
    }
}
