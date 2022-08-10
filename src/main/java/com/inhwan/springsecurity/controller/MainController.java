package com.inhwan.springsecurity.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/")
    public String root() {
        return "root";
    }

    @GetMapping("/mypage")
    public String myPage() {
        return "my page";
    }

    @GetMapping("/messages")
    public String messages() {
        return "messages";
    }

    @GetMapping("/config")
    public String config() {
        return "config";
    }
}
