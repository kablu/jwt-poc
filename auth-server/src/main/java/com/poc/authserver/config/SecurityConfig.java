package com.poc.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Default HTTP Security Configuration.
 * Order(2) — applies to all requests NOT handled by AuthorizationServerConfig (Order 1).
 *
 * Public endpoints:
 *   GET  /.well-known/jwks.json           → Custom JWKS (all 10 public keys)
 *   GET  /.well-known/openid-configuration → OIDC discovery (handled by Spring AS)
 *   GET  /oauth2/jwks                     → Spring default JWKS (handled by Spring AS)
 *   GET  /api/keys/info                   → Key metadata (dev/debug)
 *   GET  /actuator/health                 → Health check
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                // Public — JWKS and discovery endpoints
                .requestMatchers(
                    "/.well-known/jwks.json",
                    "/.well-known/openid-configuration",
                    "/oauth2/jwks",
                    "/api/keys/info",
                    "/actuator/health"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
            );

        return http.build();
    }
}
