package com.wondersgroup.web;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.Mapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author chenlin
 * @create 2020-07-30 9:20
 * @description: 首页，登录控制，工作区
 * @version：1.0
 **/
@Controller
@Slf4j
public class LoginController {


    @GetMapping(value={"/"})
    public String index(){
        log.info("index page");
        return "index";
    }

    @RequestMapping(value="/index")
    public String indexPage(){
        return "index";
    }


    @RequestMapping(value="/login")
    public String login() {
        return "redirect:/index";
    }

    @RequestMapping(value="/main")
    public String main(){
        log.info("================ main page =================");
        return "pages/main";
    }
}
