package com.poc.resourceserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Resource Server — Movie Details Service
 *
 * Responsibilities:
 *   1. Protects /api/movies/** with JWT Bearer token authentication
 *   2. Validates JWT by fetching public keys from auth-server JWKS endpoint
 *   3. Exposes provideMovieDetails API
 *
 * Flow:
 *   Client → POST http://localhost:9000/oauth2/token → receives JWT
 *   Client → GET  http://localhost:8080/api/movies   (with Bearer JWT)
 *   Resource Server validates JWT signature using auth-server's public keys
 *   → Returns movie details ✅
 *
 * Port: 8080
 * Auth Server JWKS: http://localhost:9000/.well-known/jwks.json
 */
@SpringBootApplication
public class ResourceServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(ResourceServerApplication.class, args);
    }
}
