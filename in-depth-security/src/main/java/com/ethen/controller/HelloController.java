package com.ethen.controller;

import com.ethen.common.ResponseHelper;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping
public class HelloController implements EnvironmentAware {

    private Environment env;

    @Override
    public void setEnvironment(Environment environment) {
        this.env = environment;
    }

    @RequestMapping(value = "/v1/hello", method = RequestMethod.GET)
    public Object hello() {

        String data = "Hello World !";

        return ResponseHelper.success(data, env);
    }
}
