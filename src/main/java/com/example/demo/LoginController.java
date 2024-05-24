package com.example.demo;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {

    @RequestMapping("/login/saml2/sso/okta")
    public String value() {
        System.out.println("LoginController.value ============ ");
        return "value";
    }

    @PostMapping("/login/saml2/sso/okta")
    public String login() {
        System.out.println("LoginController.value ============ ");
        return "value";
    }
}
