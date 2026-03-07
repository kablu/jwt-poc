package com.poc.jwkpoc.controller;

import com.poc.jwkpoc.entity.KeyRotationAudit;
import com.poc.jwkpoc.repository.KeyRotationAuditRepository;
import com.poc.jwkpoc.service.JwkRotationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * JWKS Discovery Controller - RFC 7517 compliant JWKS endpoint.
 */
@RestController
public class JwksController {

    private static final Logger log = LoggerFactory.getLogger(JwksController.class);

    private final JwkRotationService jwkRotationService;
    private final KeyRotationAuditRepository auditRepository;

    @Autowired
    public JwksController(JwkRotationService jwkRotationService, KeyRotationAuditRepository auditRepository) {
        this.jwkRotationService = jwkRotationService;
        this.auditRepository = auditRepository;
    }

    @Value("${jwk.issuer:https://poc.jwk-poc.local}")
    private String issuer;

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getJwks() {
        log.debug("JWKS endpoint requested");
        Map<String, Object> jwksJson = jwkRotationService.getPublicJwkSet().toJSONObject();
        return ResponseEntity.ok()
                .header("Cache-Control", "public, max-age=3600")
                .header("Access-Control-Allow-Origin", "*")
                .body(jwksJson);
    }

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

    @GetMapping("/api/admin/keys/audit")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<KeyRotationAudit>> getAuditLog() {
        List<KeyRotationAudit> audit = auditRepository.findAllByOrderByCreatedAtDesc();
        return ResponseEntity.ok(audit);
    }

    @GetMapping("/api/admin/keys/active")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getActiveKeyInfo() {
        return ResponseEntity.ok(Map.of(
                "activeKid", jwkRotationService.getActiveKid(),
                "activeKeyCount", jwkRotationService.getActiveKeyCount()
        ));
    }
}