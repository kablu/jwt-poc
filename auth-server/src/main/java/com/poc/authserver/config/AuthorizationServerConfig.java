package com.poc.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.poc.authserver.service.KeyPairRegistryService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.time.Duration;
import java.util.UUID;

/**
 * Spring Authorization Server Configuration.
 *
 * Configures:
 *   1. OAuth2 Authorization Server endpoints (token, jwks, revoke, introspect)
 *   2. OIDC support (openid-configuration, userinfo)
 *   3. JWKSource backed by 10 RSA key pairs
 *   4. Registered Client: resource-client (client_credentials grant)
 *   5. Issuer: http://localhost:9000
 *
 * Auto-exposed endpoints by Spring Authorization Server:
 *   POST /oauth2/token                        → Issue JWT
 *   GET  /oauth2/jwks                         → JWKS (auto, uses JWKSource bean)
 *   GET  /.well-known/openid-configuration    → OIDC discovery
 *   POST /oauth2/introspect                   → Token introspection
 *   POST /oauth2/revoke                       → Token revocation
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final KeyPairRegistryService keyPairRegistryService;

    /**
     * Security filter chain for Authorization Server endpoints.
     * Order(1) — highest priority, handles all /oauth2/** and OIDC endpoints.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults()); // Enable OIDC support

        http.exceptionHandling(ex -> ex
                .defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
        );

        return http.build();
    }

    /**
     * JWK Source — backed by all 10 RSA key pairs.
     *
     * Spring Authorization Server uses this to:
     *   1. Sign JWT tokens (uses private key material)
     *   2. Auto-publish /oauth2/jwks endpoint (exposes only public keys)
     *
     * Spring picks the LAST key in the set as the active signing key.
     * All 10 public keys appear in JWKS so Resource Server can verify
     * tokens signed by any of the 10 keys.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        JWKSet fullJwkSet = keyPairRegistryService.getFullJwkSet();
        return new ImmutableJWKSet<>(fullJwkSet);
    }

    /**
     * JwtDecoder — required by Spring Auth Server for OIDC ID token validation.
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Authorization Server Settings.
     * Issuer URI must match what the Resource Server uses to validate JWT iss claim.
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9000")
                .jwkSetEndpoint("/oauth2/jwks")                          // default Spring endpoint
                .tokenEndpoint("/oauth2/token")
                .oidcUserInfoEndpoint("/userinfo")
                .build();
    }

    /**
     * Registered Client — represents the Resource Server as an OAuth2 client.
     *
     * Client credentials:
     *   client-id:     resource-client
     *   client-secret: secret
     *   grant type:    client_credentials
     *   scopes:        movies:read, movies:write
     *
     * Usage:
     *   POST /oauth2/token
     *   Authorization: Basic cmVzb3VyY2UtY2xpZW50OnNlY3JldA==   (resource-client:secret)
     *   Content-Type: application/x-www-form-urlencoded
     *   grant_type=client_credentials&scope=movies:read
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient resourceClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("resource-client")
                .clientSecret("{noop}secret")                               // {noop} = plain text (dev only)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("movies:read")
                .scope("movies:write")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(resourceClient);
    }
}
