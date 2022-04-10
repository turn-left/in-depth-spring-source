package com.ethen.senarios.web.controller;

import com.ethen.common.ResponseHelper;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.core.io.Resource;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping
public class HelloController implements EnvironmentAware {

    private Environment env;

    @Override
    public void setEnvironment(Environment environment) {
        this.env = environment;
    }

    /**
     * 简单get请求 with query string
     */
    @RequestMapping(value = "/v1/hello", method = RequestMethod.GET)
    public Object hello(@RequestParam String name, @RequestParam String greetings) {

        String data = "Hello %s, %s, welcome to analysis Spring source!";
        System.err.printf(data, name, greetings);
        return ResponseHelper.success(data, env);

    }

    /**
     * 复杂请求体报文post请求
     */
    @PostMapping("/v1/complex")
    public Object complex(@RequestBody Map<String, Object> params) {
        System.err.println(params);
        return ResponseHelper.success(params, env);
    }

    /**
     * 简单文件上传请求
     */
    @PostMapping("/v1/upload")
    public void upload(MultipartFile file) {
        Resource resource = file.getResource();
        String name = file.getName();
        String originalFilename = file.getOriginalFilename();
        String contentType = file.getContentType();
        System.err.println("file upload ...");
    }
}
