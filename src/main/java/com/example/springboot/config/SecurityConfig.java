package com.example.springboot.config;

// utils
import java.util.HashSet;
import java.util.List;
import java.util.Set;

// spring core imports
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;

// SAML2.0 dependencies
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider.ResponseToken;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;

// spring security dependencies
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain configure(HttpSecurity http) throws Exception {

        // apply custom group to role converter. Not very useful if using JWT to
        // authenticate other services.
        OpenSaml4AuthenticationProvider authenticationProvider = new OpenSaml4AuthenticationProvider();
        authenticationProvider.setResponseAuthenticationConverter(groupsConverter());

        http
                .authorizeHttpRequests(authorize -> authorize.requestMatchers("/")
                        .permitAll()
                        .anyRequest().authenticated())
                .saml2Login(saml2 -> saml2
                        .authenticationManager(new ProviderManager(authenticationProvider)))
                .saml2Logout(withDefaults());

        return http.build();
    }

    /***
     * Custom converter to extract groups attributes from SAML response and attach
     * to authentication authority.
     * 
     * @return Converter
     */
    private Converter<OpenSaml4AuthenticationProvider.ResponseToken, Saml2Authentication> groupsConverter() {

        Converter<ResponseToken, Saml2Authentication> delegate = OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter();

        return (responseToken) -> {
            Saml2Authentication authentication = delegate.convert(responseToken);
            Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
            List<String> groups = principal.getAttribute("groups");
            Set<GrantedAuthority> authorities = new HashSet<>();

            // attach authorities (basically Groups in Okta context) to the authentication
            // this can be used by e.g. antMatchters().hasAuthority("group1") to filter
            // access by authority
            // may not be very useful in our case but implementing it just in case
            if (groups != null) {
                groups.stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
            } else {
                authorities.addAll(authentication.getAuthorities());
            }
            System.out.println(authorities);
            return new Saml2Authentication(principal, authentication.getSaml2Response(), authorities);
        };
    }
}