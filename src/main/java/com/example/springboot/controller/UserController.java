package com.example.springboot.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

// JWT generation
import com.example.springboot.config.JwtSecurityConstant;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.joda.time.DateTime;

import com.example.springboot.config.JwtTokenUtil;

@Controller
public class UserController {
    @RequestMapping("/")
    public String index() {
        return "home";
    }

    /***
     * Sample API Secured by Spring Security SAMl2. Entering this API without SAML2
     * authentication will redirect to SAML2 login page.
     * Success login attaches principal to the request.
     * 
     * @param principal
     *                  - retrieve the principal (user) logged in with
     *                  annotation @AuthenticationPrincipal
     * @param model
     *                  - Springboot ModelMap
     * @return
     */
    @GetMapping("/secured/hello")
    public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model)
            throws JOSEException {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        String jwt = JwtTokenUtil.generateToken(principal);
        model.addAttribute("jwt", jwt);
        return "hello";
    }

    // generate JWT, response 200 with JWT and model
    @GetMapping("/auth_token")
    public ResponseEntity<Object> login(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model)
            throws JOSEException {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        String jwt = JwtTokenUtil.generateToken(principal);
        model.addAttribute("jwt", jwt);
        return new ResponseEntity<>(model, HttpStatus.OK);
    }

}
