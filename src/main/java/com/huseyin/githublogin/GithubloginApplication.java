package com.huseyin.githublogin;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@SpringBootApplication
public class GithubloginApplication {

	public static void main(String[] args) {
		SpringApplication.run(GithubloginApplication.class, args);
	}

}

@RestController
@RequestMapping("/api")
class ApiController {

	@GetMapping("/secured")
	String secured() {
		return "Secured world!";
	}
}

@RestController
@RequestMapping("/auth")
class AuthController {

	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@GetMapping("/callback")
	public String secureEndpoint(@AuthenticationPrincipal OAuth2User oauth2User,
								 OAuth2AuthenticationToken authenticationToken) {


		OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
				authenticationToken.getAuthorizedClientRegistrationId(),
				authenticationToken.getName());
		OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
		String authorizationCode = accessToken.getTokenValue();
		// Access OAuth2 user details
		String token = JwtUtil.generateToken(oauth2User);
		return "Hello, " + oauth2User.getAttribute("login") + "! " + token + ". This is a secure endpoint!";
	}
}

@Configuration
@EnableWebSecurity
class OAuth2LoginSecurityConfig {

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
                .authorizeHttpRequests(authorizeRequests ->
						authorizeRequests.anyRequest().authenticated()
				)
                .oauth2Login((a) -> a.defaultSuccessUrl("/auth/callback"));
		return http.build();
	}
}

class JwtUtil {

	private static final String SECRET_KEY = "your-secret-key";
	private static final long EXPIRATION_TIME = 864000000; // 10 days

	public static String generateToken(OAuth2User userDetails) {
		Date now = new Date();
		Date expirationDate = new Date(now.getTime() + EXPIRATION_TIME);

		return Jwts.builder()
				.setSubject(userDetails.getAttribute("login"))
				.setIssuedAt(now)
				.setExpiration(expirationDate)
				.signWith(SignatureAlgorithm.HS512, "ssshhhhh")
				.compact();
	}
}
