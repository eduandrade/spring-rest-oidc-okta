package com.doped.okta.oidc;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

import javax.annotation.PostConstruct;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator;

@Component
public class JwtValidator {
	
	private static final Log logger = LogFactory.getLog(JwtValidator.class);
	
	@Value("${spring.security.oauth2.client.provider.okta.jwk-set-uri}")
	private String jwkSetUrl;
	
	@Value("${custom.security.okta.issuer-uri}")
	private String issuerUrl;
	
	private IDTokenValidator validator;
	
	@PostConstruct
	public void init() throws MalformedURLException {
		Issuer issuer = new Issuer(issuerUrl);
		ClientID clientID = new ClientID("api://default");
		URL jwkSetURL = new URL(jwkSetUrl);
		validator = new IDTokenValidator(issuer, clientID, JWSAlgorithm.RS256, jwkSetURL);
	}

	public boolean validate(String token) {
		logger.debug("token: " + token);
		try {
			IDTokenClaimsSet claims = validator.validate(JWTParser.parse(token), null);
			logger.info("Logged in user: [" + claims.getSubject() + "] Expire on: " + claims.getExpirationTime());
			return true;
		} catch (ParseException | BadJOSEException | JOSEException e) {
			logger.error("JWT Error", e);
		}
		return false;
	}
	
}
