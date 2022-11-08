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
     *            - retrieve the principal (user) logged in with
     *            annotation @AuthenticationPrincipal
     * @param model
     *            - Springboot ModelMap
     * @return
     */
    @RequestMapping("/secured/hello")
    public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model)
            throws JOSEException {
        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());
        String jwt = JwtTokenUtil.generateToken(principal);
        model.addAttribute("jwt", jwt);
        return "hello";
    }

    /***
     * Generate JWT after successful login.
     * TODO:
     * 1. store JWT to Redis
     * 2. implement JWT filter and validation
     * 
     * @return
     * @throws JOSEException
     */
    @GetMapping("/login")
    public ResponseEntity<String> login(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model)
            throws JOSEException {

        // final Authentication authentication =
        // SecurityContextHolder.getContext().getAuthentication();

        model.addAttribute("name", principal.getName());
        model.addAttribute("emailAddress", principal.getFirstAttribute("email"));
        model.addAttribute("userAttributes", principal.getAttributes());

        // TODO store JWT to Redis
        String jwt = generateJWT(principal);
        model.addAttribute("jwt", jwt);

        return new ResponseEntity<>(jwt, HttpStatus.OK);
    }

    private String generateJWT(Saml2AuthenticatedPrincipal principal) throws JOSEException {
        final DateTime dateTime = DateTime.now();

        // build claims
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        jwtClaimsSetBuilder.expirationTime(dateTime.plusMinutes(120).toDate());
        jwtClaimsSetBuilder.claim("name", principal.getName());
        jwtClaimsSetBuilder.claim("userAttributes", principal.getAttributes());

        // signature
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSetBuilder.build());
        signedJWT.sign(new MACSigner(JwtSecurityConstant.JWT_SECRET));
        System.out.println("JWT: " + signedJWT.serialize());

        return signedJWT.serialize();
    }

}
