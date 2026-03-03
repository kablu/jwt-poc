package com.poc.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Auth Server — Spring Authorization Server
 *
 * Responsibilities:
 *   1. Manages 10 RSA key pairs (RFC 7517 JWK)
 *   2. Exposes /.well-known/jwks.json  → 10 public keys
 *   3. Exposes /oauth2/jwks            → same (Spring default)
 *   4. Issues JWT access tokens via POST /oauth2/token
 *   5. Exposes /.well-known/openid-configuration for OIDC discovery
 *
 * Ports: 9000
 */
@SpringBootApplication
public class AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }
}
