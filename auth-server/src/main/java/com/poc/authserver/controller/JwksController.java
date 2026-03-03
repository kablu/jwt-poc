package com.poc.authserver.controller;

import com.poc.authserver.service.KeyPairRegistryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * JWKS Controller — RFC 7517 compliant public endpoints.
 *
 * ┌────────────────────────────────────────────────────────────────┐
 * │  PUBLIC — No authentication required                           │
 * │                                                                │
 * │  GET /.well-known/jwks.json   → 10 RSA public keys (custom)   │
 * │  GET /api/keys/info           → Key metadata (no key material) │
 * └────────────────────────────────────────────────────────────────┘
 *
 * NOTE: Spring Authorization Server ALSO auto-exposes /oauth2/jwks
 *       with the same content. Both endpoints serve the same 10 public keys.
 *
 * CRITICAL SECURITY:
 *   getPublicJwkSet() is called — ONLY public key parameters are returned.
 *   Private key parameters (d, p, q, dp, dq, qi) are NEVER included.
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final KeyPairRegistryService keyPairRegistryService;

    /**
     * Custom JWKS endpoint — returns all 10 RSA public keys.
     *
     * Response format (RFC 7517 §5):
     * {
     *   "keys": [
     *     { "kty":"RSA", "kid":"auth-server-key-01", "use":"sig", "alg":"RS256", "n":"...", "e":"AQAB" },
     *     { "kty":"RSA", "kid":"auth-server-key-02", ... },
     *     ...
     *     { "kty":"RSA", "kid":"auth-server-key-10", ... }
     *   ]
     * }
     *
     * Cache-Control: public, max-age=3600 — Resource Servers can cache for 1 hour.
     * Access-Control-Allow-Origin: *       — Cross-origin access allowed.
     */
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.debug("JWKS requested — serving {} public keys", keyPairRegistryService.getTotalKeyCount());

        Map<String, Object> jwksJson = keyPairRegistryService
                .getPublicJwkSet()
                .toJSONObject();            // toJSONObject() = public keys only (no private params)

        return ResponseEntity.ok()
                .header("Cache-Control", "public, max-age=3600")
                .header("Access-Control-Allow-Origin", "*")
                .body(jwksJson);
    }

    /**
     * Key Metadata endpoint — returns info about all 10 key pairs.
     * Only exposes kid, algorithm, keyType, keyUse — NO key material.
     * Useful for debugging and monitoring.
     */
    @GetMapping(value = "/api/keys/info", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getKeyInfo() {
        List<Map<String, String>> metadata = keyPairRegistryService.getKeyMetadata();

        return ResponseEntity.ok(Map.of(
                "totalKeyPairs", keyPairRegistryService.getTotalKeyCount(),
                "algorithm",     "RS256",
                "keySize",       "RSA-2048",
                "keys",          metadata,
                "jwksEndpoints", List.of(
                        "http://localhost:9000/.well-known/jwks.json",
                        "http://localhost:9000/oauth2/jwks"
                )
        ));
    }
}
