package com.example.uaaoauth2;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {
    @GetMapping("/")
    String index() {
        return "index";
    }

    @GetMapping("login")
    String login() {
        return "login";
    }
}