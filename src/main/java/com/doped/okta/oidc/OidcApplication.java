package com.doped.okta.oidc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class OidcApplication {

	public static void main(String[] args) {
		System.setProperty("http.proxyHost","host");
	    System.setProperty("http.proxyPort","port");
	    System.setProperty("https.proxyHost","host");
	    System.setProperty("https.proxyPort","port");
		    
		SpringApplication.run(OidcApplication.class, args);
	}
}
