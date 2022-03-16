package com.ethen.webapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * PortalController
 *
 * @author ethenyang@126.com
 * @since 2022/03/16
 */
@Controller
public class PortalController {
    @RequestMapping("index")
    public Object index() {
        return "index";
    }
}
