package com.ethen.webapp.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RestController;

/**
 * Spring根容器
 * <p>
 * 扫描排除controller层
 *
 * @author ethenyang@126.com
 * @since 2022/03/16
 */
@Configuration
@ComponentScan(basePackages = {"com.ethen.webapp"}, excludeFilters = {
        @ComponentScan.Filter(type = FilterType.ANNOTATION, value = {RestController.class, Controller.class}),
        @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, value = {WebAppConfig.class})
})
public class RootAppConfig {
}
