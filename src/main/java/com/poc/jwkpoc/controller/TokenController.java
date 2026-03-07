package com.poc.jwkpoc.controller;

import com.poc.jwkpoc.model.TokenRequest;
import com.poc.jwkpoc.model.TokenResponse;
import com.poc.jwkpoc.service.AudienceRegistryService;
import com.poc.jwkpoc.service.JwtSigningService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Token Management Controller.
 */
@RestController
@RequestMapping("/api")
public class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController.class);

    private final JwtSigningService         jwtSigningService;
    private final AudienceRegistryService   audienceRegistryService;

    @Autowired
    public TokenController(JwtSigningService jwtSigningService,
                           AudienceRegistryService audienceRegistryService) {
        this.jwtSigningService       = jwtSigningService;
        this.audienceRegistryService = audienceRegistryService;
    }

    /**
     * JWT Token issue karo.
     * POST /api/auth/token
     *
     * Pehle check karta hai: kya requested audiences registered hain?
     * Agar nahi → 400 Bad Request
     * Agar haan  → Signed JWT return karta hai
     */
    @PostMapping("/auth/token")
    public ResponseEntity<?> issueToken(@Valid @RequestBody TokenRequest request) {
        log.info("Token issuance request: subject={}, audiences={}", request.getSubject(), request.getAudiences());

        // ── Audience Registry Validation ──────────────────────────────────
        if (request.getAudiences() != null && !request.getAudiences().isEmpty()) {
            List<String> unregistered = request.getAudiences().stream()
                    .filter(aud -> !audienceRegistryService.isValidAudience(aud))
                    .collect(Collectors.toList());

            if (!unregistered.isEmpty()) {
                log.warn("Token rejected — unregistered audiences: {}", unregistered);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "error",   "AUDIENCE_NOT_REGISTERED",
                    "message", "Ye audiences auth-server mein registered nahi hain: " + unregistered,
                    "hint",    "Pehle POST /api/audiences/register call karo"
                ));
            }
        }
        // ─────────────────────────────────────────────────────────────────

        TokenResponse response = jwtSigningService.issueToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/verify")
    public ResponseEntity<Map<String, Object>> verifyToken(@RequestBody Map<String, String> body) {
        String tokenToVerify = body.get("token");
        if (tokenToVerify == null || tokenToVerify.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "token field is required"));
        }
        log.debug("JWT verification requested");
        Map<String, Object> claims = jwtSigningService.parseUnverified(tokenToVerify);
        return ResponseEntity.ok(Map.of(
                "status", "valid",
                "claims", claims
        ));
    }

    @GetMapping("/protected/me")
    public ResponseEntity<Map<String, Object>> getCurrentUser(@AuthenticationPrincipal Jwt jwt) {
        log.debug("Authenticated user info requested for subject={}", jwt.getSubject());
        return ResponseEntity.ok(Map.of(
                "subject", jwt.getSubject(),
                "issuer", jwt.getIssuer(),
                "issuedAt", jwt.getIssuedAt(),
                "expiresAt", jwt.getExpiresAt(),
                "audiences", jwt.getAudience(),
                "claims", jwt.getClaims(),
                "keyId", jwt.getHeaders().getOrDefault("kid", "unknown")
        ));
    }

    @GetMapping("/protected/hello")
    public ResponseEntity<Map<String, String>> hello(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of(
                "message", "Hello, " + jwt.getSubject() + "! Your JWT is valid.",
                "kid", (String) jwt.getHeaders().getOrDefault("kid", "unknown")
        ));
    }
}