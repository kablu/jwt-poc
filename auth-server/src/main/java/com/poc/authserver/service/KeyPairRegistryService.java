package com.poc.authserver.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * PKI Key Pair Registry Service.
 *
 * Generates and manages exactly 10 RSA-2048 key pairs on application startup.
 * Each key pair is assigned a unique kid: auth-server-key-01 to auth-server-key-10.
 *
 * KEY SECURITY RULE:
 *   - Private keys are kept ONLY in memory (never persisted, never exposed via API)
 *   - getPublicJwkSet() strips all private key material before serving
 *   - getFullJwkSet() is used ONLY internally by Spring Auth Server for JWT signing
 */
@Slf4j
@Service
public class KeyPairRegistryService {

    private static final int TOTAL_KEY_PAIRS = 10;
    private static final int RSA_KEY_SIZE    = 2048;

    /** Internal store: full key pairs (public + private). NEVER expose externally. */
    private final List<RSAKey> fullKeyPairs = new ArrayList<>();

    @PostConstruct
    public void generateAllKeyPairs() {
        log.info("========================================");
        log.info("  Generating {} RSA-{} key pairs...", TOTAL_KEY_PAIRS, RSA_KEY_SIZE);
        log.info("========================================");

        for (int i = 1; i <= TOTAL_KEY_PAIRS; i++) {
            String kid = String.format("auth-server-key-%02d", i);
            try {
                RSAKey rsaKey = new RSAKeyGenerator(RSA_KEY_SIZE)
                        .keyUse(KeyUse.SIGNATURE)
                        .algorithm(JWSAlgorithm.RS256)
                        .keyID(kid)
                        .generate();
                fullKeyPairs.add(rsaKey);
                log.info("  ✅ Generated key pair [{}/{}]: kid={}", i, TOTAL_KEY_PAIRS, kid);
            } catch (JOSEException e) {
                throw new RuntimeException("Failed to generate RSA key pair: " + kid, e);
            }
        }
        log.info("========================================");
        log.info("  All {} RSA key pairs ready.", TOTAL_KEY_PAIRS);
        log.info("========================================");
    }

    /**
     * Returns all 10 RSA keys (public + private).
     * USED ONLY by Spring Authorization Server's JWKSource for JWT signing.
     * NEVER expose this externally.
     */
    public List<RSAKey> getAllFullKeyPairs() {
        return Collections.unmodifiableList(fullKeyPairs);
    }

    /**
     * Returns a JWKSet with ALL 10 full key pairs (public + private).
     * ONLY for Spring Auth Server internal use (JWT signing via NimbusJwtEncoder).
     */
    public JWKSet getFullJwkSet() {
        return new JWKSet(new ArrayList<>(fullKeyPairs));
    }

    /**
     * Returns a JWKSet with ONLY public key material.
     * Safe to serve over HTTP — no private key parameters (d, p, q, dp, dq, qi).
     * This is what /.well-known/jwks.json returns.
     */
    public JWKSet getPublicJwkSet() {
        List<JWK> publicKeys = fullKeyPairs.stream()
                .map(RSAKey::toPublicJWK)
                .collect(Collectors.toList());
        return new JWKSet(publicKeys);
    }

    /**
     * Returns a summary of all key pair metadata (kid + algorithm only).
     * No key material included.
     */
    public List<Map<String, String>> getKeyMetadata() {
        return fullKeyPairs.stream()
                .map(k -> Map.of(
                        "kid",       k.getKeyID(),
                        "algorithm", k.getAlgorithm().getName(),
                        "keyType",   k.getKeyType().getValue(),
                        "keyUse",    k.getKeyUse().identifier()
                ))
                .collect(Collectors.toList());
    }

    public int getTotalKeyCount() {
        return fullKeyPairs.size();
    }
}
