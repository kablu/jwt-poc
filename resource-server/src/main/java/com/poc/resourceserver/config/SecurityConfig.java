package com.poc.resourceserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource Server Security Configuration — Approach 1 (Auto JWKS).
 *
 * JWT Validation Flow:
 *   1. Client sends request with "Authorization: Bearer <JWT>"
 *   2. NimbusJwtDecoder fetches public keys from auth-server's JWKS endpoint
 *      → GET http://localhost:9000/.well-known/jwks.json (cached by Spring)
 *   3. Finds the key matching the JWT's "kid" header parameter
 *   4. Verifies JWT signature using the matched RSA public key
 *   5. Validates: expiry (exp), issuer (iss)
 *   6. Grants access if all validations pass ✅
 *
 * If auth-server rotates keys:
 *   → JWT has new kid → NimbusJwtDecoder doesn't find it in cache
 *   → Automatically re-fetches JWKS from auth-server
 *   → Verifies with updated key set
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${auth-server.jwks-uri}")
    private String jwksUri;

    @Value("${auth-server.issuer-uri}")
    private String issuerUri;

    /**
     * HTTP Security — stateless JWT-based resource server.
     *
     * Protected endpoints (JWT required):
     *   GET /api/movies/**        → movies:read scope
     *
     * Public endpoints:
     *   GET /actuator/health      → Health check
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder()))
            );

        return http.build();
    }

    /**
     * JwtDecoder — Approach 1: Spring Security OAuth2 Resource Server.
     *
     * Configured with:
     *   - JWKS URI: points to auth-server's /.well-known/jwks.json
     *   - Algorithm: RS256 (matches auth-server's signing algorithm)
     *   - Issuer validator: ensures JWT was issued by our trusted auth-server
     *   - Timestamp validator: rejects expired tokens (built-in)
     *
     * Spring Security auto-caches the JWKS (5-min default TTL).
     * On kid mismatch → auto-refetch from auth-server JWKS endpoint.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(jwksUri)
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();

        // Validate issuer claim matches our trusted auth-server
        OAuth2TokenValidator<Jwt> issuerValidator =
                JwtValidators.createDefaultWithIssuer(issuerUri);

        // Compose: issuer + expiry validators
        OAuth2TokenValidator<Jwt> compositeValidator =
                new DelegatingOAuth2TokenValidator<>(issuerValidator);

        decoder.setJwtValidator(compositeValidator);
        return decoder;
    }
}
