package com.example.springboot;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
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

@SpringBootApplication
@Controller
public class Application {

	public static void main(String[] args) {
		SpringApplication.run(Application.class, args);
	}

	@RequestMapping("/")
	public String index() {
		return "home";
	}

	/***
	 * Sample API Secured by Spring Security SAMl2.
	 * Entering this API without SAML2 authentication will redirect to SAML2 login
	 * page.
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
	public String hello(@AuthenticationPrincipal Saml2AuthenticatedPrincipal principal, Model model) {
		model.addAttribute("name", principal.getName());
		return "hello";
	}

	/***
	 * WIP WIP WIP
	 * Generate JWT after successful login.
	 * TODO:
	 * 1. store JWT to Redis
	 * 2. implement JWT filter and validation
	 * 3. integrate this with SAML authentication
	 * 
	 * @return
	 * @throws JOSEException
	 */
	@GetMapping("/login")
	public ResponseEntity<String> login() throws JOSEException {

		// final Authentication authentication =
		// SecurityContextHolder.getContext().getAuthentication();

		final DateTime dateTime = DateTime.now();

		// build claims
		JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
		jwtClaimsSetBuilder.expirationTime(dateTime.plusMinutes(120).toDate());
		jwtClaimsSetBuilder.claim("APP", "SAMPLE");

		// signature
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), jwtClaimsSetBuilder.build());
		signedJWT.sign(new MACSigner(JwtSecurityConstant.JWT_SECRET));

		return new ResponseEntity<>(signedJWT.serialize(), HttpStatus.OK);
	}

}
