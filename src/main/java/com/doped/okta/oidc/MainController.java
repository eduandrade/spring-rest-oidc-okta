package com.doped.okta.oidc;

import java.util.Collections;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Controller
public class MainController {
	
	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;
	
	@Autowired
	private JwtValidator jwtValidator;

	/*
	 * @GetMapping("/") String home(Principal user) { return "Hello " +
	 * user.getName(); }
	 */

	@RequestMapping("/")
	public String index(Model model, OAuth2AuthenticationToken authentication) {
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
		model.addAttribute("userName", authentication.getName());
		model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
		return "index";
	}

	@RequestMapping("/userinfo")
	public String userinfo(Model model, OAuth2AuthenticationToken authentication) {
		OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication);
		Map userAttributes = Collections.emptyMap();
		String userInfoEndpointUri = authorizedClient.getClientRegistration().getProviderDetails().getUserInfoEndpoint()
				.getUri();
		if (!StringUtils.isEmpty(userInfoEndpointUri) && jwtValidator.validate(authorizedClient.getAccessToken().getTokenValue())) { // userInfoEndpointUri is optional for OIDC Clients

			ReactorClientHttpConnector connector = new ReactorClientHttpConnector(
					options -> options.httpProxy(addressSpec -> {
						return addressSpec
								.host("host")
								.port(3128)
								.username("user")
								.password(pass -> "pass");
					}));
			userAttributes = WebClient.builder().clientConnector(connector).filter(oauth2Credentials(authorizedClient))
					.build().get().uri(userInfoEndpointUri).retrieve().bodyToMono(Map.class).block();
		}
		model.addAttribute("userAttributes", userAttributes);
		return "userinfo";
	}

	private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
		return this.authorizedClientService.loadAuthorizedClient(authentication.getAuthorizedClientRegistrationId(),
				authentication.getName());
	}

	private ExchangeFilterFunction oauth2Credentials(OAuth2AuthorizedClient authorizedClient) {
		return ExchangeFilterFunction.ofRequestProcessor(clientRequest -> {
			ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
					.header(HttpHeaders.AUTHORIZATION, "Bearer " + authorizedClient.getAccessToken().getTokenValue())
					.build();
			return Mono.just(authorizedRequest);
		});
	}

}
