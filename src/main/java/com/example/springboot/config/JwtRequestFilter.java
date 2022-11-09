package com.example.springboot.config;

import java.io.IOException;
import java.text.ParseException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.springboot.service.JwtUserDetailsService;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUserDetailsService jwtUserDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain)
            throws ServletException, IOException {

        final String requestTokenHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;
        // JWT Token is in the form "Bearer token". Remove Bearer word and get
        // only the Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
                System.out.println("username: " + username);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ParseException e) {
                e.printStackTrace();
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        System.out.println(SecurityContextHolder.getContext().getAuthentication());
        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.jwtUserDetailsService.loadUserByUsername(username);

            // if token is valid configure Spring Security to manually set
            // authentication
            try {
                if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                    // UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
                    // UsernamePasswordAuthenticationToken(
                    // userDetails, null, userDetails.getAuthorities());
                    // usernamePasswordAuthenticationToken
                    // .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // // After setting the Authentication in the context, we specify
                    // // that the current user is authenticated. So it passes the
                    // // Spring Security Configurations successfully.
                    // SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

                    // TODO: do some stuff here to validate JWT against redis cache
                } else {
                    // TODO response 401 and remove SAML2 user form context
                    response.sendError(
                            HttpServletResponse.SC_UNAUTHORIZED,
                            "The token is not valid.");

                }
            } catch (ParseException e) {
                e.printStackTrace();
            }
        } else {
            // TODO response 401 and remove SAML2 user form context
            System.out.print("Should be 401");
        }
        chain.doFilter(request, response);
    }

    // do not filter root path and /login
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getServletPath();
        return (path.equals("/") ||
                path.startsWith("/login") ||
                path.startsWith("/logout") ||
                path.equals("/auth_token"));
    }

}