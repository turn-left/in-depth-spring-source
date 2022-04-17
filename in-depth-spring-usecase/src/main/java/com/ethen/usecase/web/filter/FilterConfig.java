package com.ethen.usecase.web.filter;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {
    @Value("${account.content-length.list:/**/export;/**/download;/**/import}")
    private String requestList;

    @Bean
    public FilterRegistrationBean<ContentLengthFilter> filterRegistrationBean() {
        FilterRegistrationBean<ContentLengthFilter> filterRegistrater = new FilterRegistrationBean<>();
        filterRegistrater.setFilter(new ContentLengthFilter(requestList));
        return filterRegistrater;
    }

}
