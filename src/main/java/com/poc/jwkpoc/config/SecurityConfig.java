package com.poc.jwkpoc.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.poc.jwkpoc.service.JwkRotationService;
import com.poc.jwkpoc.validator.AudienceValidator;
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
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

/**
 * Security Configuration — Approach 1: Spring Security OAuth2 Resource Server.
 *
 * Configures:
 *   1. JWT-based stateless authentication
 *   2. Custom JwtDecoder with audience validation
 *   3. Role extraction from JWT "roles" claim
 *   4. Public endpoints for JWKS and token issuance
 *   5. H2 console access (dev only)
 *
 * The JwtDecoder resolves keys from the application's own JWKS endpoint,
 * implementing the full Authorization Server + Resource Server pattern in one service.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final JwkRotationService jwkRotationService;

    @Autowired
    public SecurityConfig(JwkRotationService jwkRotationService) {
        this.jwkRotationService = jwkRotationService;
    }

    @Value("${jwk.issuer:https://poc.jwk-poc.local}")
    private String issuer;

    @Value("${jwk.audiences:jwk-poc-api}")
    private List<String> audiences;

    /**
     * HTTP Security filter chain.
     *
     * Public endpoints (no JWT required):
     *   GET  /.well-known/jwks.json         — JWKS discovery
     *   POST /api/auth/token                 — Token issuance
     *   GET  /actuator/health                — Health check
     *   GET  /h2-console/**                  — H2 console (dev)
     *
     * Secured endpoints (JWT Bearer token required):
     *   GET  /api/protected/**
     *   GET  /api/audit/**
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin())) // H2 console
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/.well-known/jwks.json",
                    "/.well-known/openid-configuration",
                    "/api/auth/token",
                    "/api/audiences/**",          // Audience registration — public
                    "/actuator/health",
                    "/actuator/info",
                    "/h2-console/**"
                ).permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder(jwkSource()))
                    .jwtAuthenticationConverter(jwtAuthenticationConverter())
                )
            );

        return http.build();
    }

    /**
     * JwtDecoder — Approach 1 (Auto JWKS) combined with Approach 2 (Nimbus manual).
     *
     * Instead of pointing to an external JWKS URI, we decode directly from the
     * application's own JWKSource. This avoids an HTTP round-trip and is suitable
     * for the combined Auth+Resource server pattern.
     *
     * Validators applied:
     *   1. JwtTimestampValidator — rejects expired tokens
     *   2. JwtIssuerValidator    — validates iss claim
     *   3. AudienceValidator     — validates aud claim (custom, RFC 7519 §4.1.3)
     */
    /**
     * JWK Source bean — always reflects the current in-memory key store
     * (supports key rotation without restart).
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        return (jwkSelector, context) -> jwkSelector.select(jwkRotationService.getPublicJwkSet());
    }

    /**
     * JwtDecoder — Approach 1 (Spring OAuth2 Resource Server) with custom validators.
     *
     * Decodes and validates incoming JWT Bearer tokens using the application's own
     * JWKSource (avoids HTTP round-trip to external JWKS URI).
     *
     * Validators applied:
     *   1. JwtTimestampValidator — rejects expired tokens
     *   2. JwtIssuerValidator    — validates iss claim
     *   3. AudienceValidator     — validates aud claim (custom, RFC 7519 §4.1.3)
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri("http://localhost:8080/.well-known/jwks.json")
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();

        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuer);
        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(audiences);
        OAuth2TokenValidator<Jwt> compositeValidator = new DelegatingOAuth2TokenValidator<>(
                defaultValidators,
                audienceValidator
        );

        decoder.setJwtValidator(compositeValidator);
        return decoder;
    }

    /**
     * Extract authorities from the "roles" claim in the JWT.
     * Roles are prefixed with "ROLE_" to satisfy Spring Security conventions.
     *
     * Example JWT claim: { "roles": ["ADMIN", "USER"] }
     * → Granted authorities: [ROLE_ADMIN, ROLE_USER]
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
        converter.setAuthoritiesClaimName("roles");
        converter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter authConverter = new JwtAuthenticationConverter();
        authConverter.setJwtGrantedAuthoritiesConverter(converter);
        return authConverter;
    }
}
