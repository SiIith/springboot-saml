package com.example.springboot.config;

import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.AntPathMatcher;

@Configuration
public class SecurityConfiguration {

	@Bean
	SecurityFilterChain app(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests(authorize -> 
				authorize.antMatchers("/") // match a url pattern to "not secure"
				.permitAll()
				.anyRequest().authenticated()
			)
			.saml2Login(Customizer.withDefaults())
			.saml2Logout(Customizer.withDefaults());
		// @formatter:on

		return http.build();
	}

	// SAML xml metadata, can be local or http
	private String metaDataLocation = "https://dev-07053288.okta.com/app/exk74570pmJ9GEiDR5d7/sso/saml/metadata";
	// SLO endpoint, should be the same to SSO endpoint
	private String singleLogoutServiceLocation = "https://dev-07053288.okta.com/app/dev-07053288_mytestapp_1/exk74570pmJ9GEiDR5d7/slo/saml";

	@Bean
	RelyingPartyRegistrationResolver relyingPartyRegistrationResolver(
			RelyingPartyRegistrationRepository registrations) {
		return new DefaultRelyingPartyRegistrationResolver(registrations);
	}

	@Bean
	FilterRegistrationBean<Saml2MetadataFilter> metadata(RelyingPartyRegistrationResolver registrations) {
		Saml2MetadataFilter metadata = new Saml2MetadataFilter(registrations, new OpenSamlMetadataResolver());
		FilterRegistrationBean<Saml2MetadataFilter> filter = new FilterRegistrationBean<>(metadata);
		filter.setOrder(-101);
		return filter;
	}

	@Bean
	RelyingPartyRegistrationRepository repository(
			@Value("classpath:credentials/local.key") RSAPrivateKey privateKey) {
				
		RelyingPartyRegistration registration = RelyingPartyRegistrations
				.fromMetadataLocation(metaDataLocation)
				.registrationId("okta-saml")
				.signingX509Credentials(
						(c) -> c.add(Saml2X509Credential.signing(privateKey, relyingPartyCertificate())))
				.singleLogoutServiceLocation(singleLogoutServiceLocation)
				.singleLogoutServiceResponseLocation("http://localhost:8080/logout/saml2/slo")
				.singleLogoutServiceBinding(Saml2MessageBinding.POST).build();
		return new InMemoryRelyingPartyRegistrationRepository(registration);
	}

	// SLO certificate
	X509Certificate relyingPartyCertificate() {
		Resource resource = new ClassPathResource("credentials/local.crt");
		try (InputStream is = resource.getInputStream()) {
			return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
		} catch (Exception ex) {
			throw new UnsupportedOperationException(ex);
		}
	}

}