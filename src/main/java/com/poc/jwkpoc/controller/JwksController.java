package com.poc.jwkpoc.controller;

import com.poc.jwkpoc.entity.KeyRotationAudit;
import com.poc.jwkpoc.repository.KeyRotationAuditRepository;
import com.poc.jwkpoc.service.JwkRotationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * JWKS Discovery Controller — RFC 7517 compliant JWKS endpoint.
 *
 * Implements Approach 1 (OAuth2 Resource Server) by publishing the JWKS endpoint
 * that Spring Security's NimbusJwtDecoder fetches to verify incoming JWT signatures.
 *
 * PUBLIC endpoints (no authentication required):
 *   GET /.well-known/jwks.json               — JWKS (public keys only)
 *   GET /.well-known/openid-configuration    — OIDC discovery metadata
 *
 * ADMIN endpoints (ROLE_ADMIN required):
 *   POST /api/admin/keys/rotate               — Manual key rotation trigger
 *   GET  /api/admin/keys/audit                — Key rotation audit log
 */
@Slf4j
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwkRotationService jwkRotationService;
    private final KeyRotationAuditRepository auditRepository;

    @Value("${jwk.issuer:https://poc.jwk-poc.local}")
    private String issuer;

    /**
     * JWKS Endpoint — RFC 7517 §5
     *
     * Returns the JSON Web Key Set containing ONLY public keys.
     * Cache-Control header allows clients to cache for 1 hour.
     *
     * CRITICAL SECURITY: Private key material is NEVER included here.
     * toPublicJWKSet() strips all private parameters (d, p, q, dp, dq, qi).
     */
    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.debug("JWKS endpoint requested");
        Map<String, Object> jwksJson = jwkRotationService.getPublicJwkSet().toJSONObject();

        return ResponseEntity.ok()
                .header("Cache-Control", "public, max-age=3600")
                .header("Access-Control-Allow-Origin", "*")
                .body(jwksJson);
    }

    /**
     * OIDC Discovery Endpoint — RFC 8414
     *
     * Provides OpenID Connect discovery metadata including the JWKS URI.
     * Allows clients to auto-discover the JWKS endpoint location.
     */
    @GetMapping(value = "/.well-known/openid-configuration", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> openidConfiguration() {
        Map<String, Object> discovery = Map.of(
                "issuer", issuer,
                "jwks_uri", issuer + "/.well-known/jwks.json",
                "token_endpoint", issuer + "/api/auth/token",
                "response_types_supported", List.of("token"),
                "subject_types_supported", List.of("public"),
                "id_token_signing_alg_values_supported", List.of("RS256"),
                "grant_types_supported", List.of("client_credentials"),
                "token_endpoint_auth_methods_supported", List.of("none")
        );
        return ResponseEntity.ok(discovery);
    }

    /**
     * Admin: Trigger manual key rotation.
     * Requires ROLE_ADMIN authority.
     */
    @PostMapping("/api/admin/keys/rotate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> triggerRotation(
            @RequestParam(defaultValue = "manual-admin-request") String reason) {

        log.info("Manual key rotation requested with reason={}", reason);
        jwkRotationService.rotateKey(reason);

        return ResponseEntity.ok(Map.of(
                "status", "rotated",
                "activeKid", jwkRotationService.getActiveKid(),
                "activeKeyCount", jwkRotationService.getActiveKeyCount(),
                "reason", reason
        ));
    }

    /**
     * Admin: Retrieve key rotation audit trail from H2 database.
     * Requires ROLE_ADMIN authority.
     */
    @GetMapping("/api/admin/keys/audit")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<KeyRotationAudit>> getAuditLog() {
        List<KeyRotationAudit> audit = auditRepository.findAllByOrderByCreatedAtDesc();
        return ResponseEntity.ok(audit);
    }

    /**
     * Admin: Current active key info (kid only — no private key material).
     */
    @GetMapping("/api/admin/keys/active")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getActiveKeyInfo() {
        return ResponseEntity.ok(Map.of(
                "activeKid", jwkRotationService.getActiveKid(),
                "activeKeyCount", jwkRotationService.getActiveKeyCount()
        ));
    }
}
