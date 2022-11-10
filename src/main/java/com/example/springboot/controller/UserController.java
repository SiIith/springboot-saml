package com.example.springboot.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class UserController {
    @RequestMapping("/")
    public String index() {
        return "home";
    }

    // generate JWT, response 200 with JWT and model
    @GetMapping("/auth-token")
    public ResponseEntity<Object> login(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        return new ResponseEntity<>(model, HttpStatus.OK);
    }

}
