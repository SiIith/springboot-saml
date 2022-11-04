// package com.example.springboot;

// import java.io.File;
// import java.security.cert.X509Certificate;

// import javax.servlet.http.HttpServletRequest;

// import org.opensaml.security.x509.X509Support;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.core.convert.converter.Converter;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// import org.springframework.security.saml2.core.Saml2X509Credential;
// import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
// import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
// import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
// import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
// import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
// import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
// import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig extends WebSecurityConfigurerAdapter {

//     private String identityProviderIssuer = "http://www.okta.com/exk74570pmJ9GEiDR5d7";
//     private String singleSignOnURL = "https://dev-07053288.okta.com/app/dev-07053288_mytestapp_1/exk74570pmJ9GEiDR5d7/sso/saml";

//     @Autowired
//     private RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

//     @Override
//     protected void configure(HttpSecurity http) throws Exception {
//         // Enable SAML2 login
//         http
//                 .authorizeRequests(authorize -> authorize.antMatchers("/").permitAll().anyRequest().authenticated())
//                 .saml2Login();

//         // add auto-generation of ServiceProvider Metadata XML file
//         Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationResolver = new DefaultRelyingPartyRegistrationResolver(
//                 relyingPartyRegistrationRepository);
//         Saml2MetadataFilter filter = new Saml2MetadataFilter(relyingPartyRegistrationResolver,
//                 new OpenSamlMetadataResolver());
//         http.addFilterBefore(filter, Saml2WebSsoAuthenticationFilter.class);
//     }

//     @Bean
//     protected RelyingPartyRegistrationRepository relyingPartyRegistrations() throws Exception {
//         ClassLoader classLoader = getClass().getClassLoader();
//         File verificationKey = new File(classLoader.getResource("saml-certificate/okta.cert").getFile());
//         X509Certificate certificate = X509Support.decodeCertificate(verificationKey);
//         Saml2X509Credential credential = Saml2X509Credential.verification(certificate);
//         RelyingPartyRegistration registration = RelyingPartyRegistration
//                 .withRegistrationId("okta-saml")
//                 .assertingPartyDetails(party -> party
//                         .entityId(identityProviderIssuer)
//                         .singleSignOnServiceLocation(singleSignOnURL)
//                         .wantAuthnRequestsSigned(false)
//                         .verificationX509Credentials(c -> c.add(credential)))
//                 .build();
//         return new InMemoryRelyingPartyRegistrationRepository(registration);
//     }

// }