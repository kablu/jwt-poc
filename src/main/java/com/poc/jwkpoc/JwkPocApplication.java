package com.poc.jwkpoc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * JWK (JSON Web Key) — Proof of Concept Application
 *
 * Implements RFC 7517 — JSON Web Key specification.
 * Approach 1: Spring Security OAuth2 Resource Server with Auto JWKS verification.
 *
 * The application acts as both:
 *   - Authorization Server: generates RSA key pair, signs JWTs, exposes JWKS endpoint
 *   - Resource Server: verifies incoming JWTs using its own JWKS endpoint
 */
@SpringBootApplication
@EnableScheduling
public class JwkPocApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwkPocApplication.class, args);
    }
}
