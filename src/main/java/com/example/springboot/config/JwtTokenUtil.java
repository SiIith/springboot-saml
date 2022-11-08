package com.example.springboot.config;

import java.io.Serializable;
import java.text.ParseException;
import java.util.Date;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.joda.time.DateTime;

import com.nimbusds.jose.*;
import com.nimbusds.jwt.*;
import com.nimbusds.jose.crypto.MACSigner;

@Component
public class JwtTokenUtil implements Serializable {

    // private String secret = JwtSecurityConstant.JWT_SECRET;

    // retrieve username from jwt token
    public String getUsernameFromToken(String token) throws ParseException {
        final JWTClaimsSet claims = getAllClaimsFromToken(token);
        return claims.getStringClaim("name");
    }

    // retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) throws ParseException {
        final JWTClaimsSet claims = getAllClaimsFromToken(token);
        return claims.getExpirationTime();
    }

    // retrieve JWT claims from JWT string
    private JWTClaimsSet getAllClaimsFromToken(String jwt) throws ParseException {
        SignedJWT signedJWT = SignedJWT.parse(jwt);
        return signedJWT.getJWTClaimsSet();
    }

    // retrieve a specific claim from JWT string
    public <T> T getClaimFromToken(String token, Function<JWTClaimsSet, T> claimsResolver) {
        try {
            final JWTClaimsSet claims = getAllClaimsFromToken(token);
            return claimsResolver.apply(claims);
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return null;
    }

    // check if the token has expired
    private Boolean isTokenExpired(String token) throws ParseException {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    // validate token
    public Boolean validateToken(String token, UserDetails userDetails) throws ParseException {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    public static String generateToken(Saml2AuthenticatedPrincipal principal) throws JOSEException {
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
