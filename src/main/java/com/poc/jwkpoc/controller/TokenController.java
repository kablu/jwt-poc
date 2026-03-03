package com.poc.jwkpoc.controller;

import com.poc.jwkpoc.model.TokenRequest;
import com.poc.jwkpoc.model.TokenResponse;
import com.poc.jwkpoc.service.JwtSigningService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Token Management Controller.
 *
 * Public endpoint:
 *   POST /api/auth/token      — Issue a signed JWT
 *
 * Protected endpoints (JWT Bearer required):
 *   POST /api/auth/verify     — Verify a JWT and return its claims
 *   GET  /api/protected/me    — Return current authenticated user's JWT claims
 */
@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class TokenController {

    private final JwtSigningService jwtSigningService;

    /**
     * Issue a signed JWT.
     *
     * Uses Approach 1 signing flow:
     *   1. JwkRotationService provides the current active RSA private key
     *   2. JWT is signed with RS256 algorithm
     *   3. kid header is set for JWKS key matching
     *
     * Public endpoint — no authentication required.
     *
     * @param request Token request containing subject, audiences, roles, expiry
     * @return Signed JWT access token with metadata
     */
    @PostMapping("/auth/token")
    public ResponseEntity<TokenResponse> issueToken(@Valid @RequestBody TokenRequest request) {
        log.info("Token issuance request for subject={}", request.getSubject());
        TokenResponse response = jwtSigningService.issueToken(request);
        return ResponseEntity.ok(response);
    }

    /**
     * Verify a JWT and return its claims.
     * Protected endpoint — requires a valid JWT Bearer token.
     *
     * @param tokenToVerify The JWT string to verify
     * @return Parsed claims from the verified JWT
     */
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

    /**
     * Protected: Return the current authenticated user's JWT claims.
     * Demonstrates that Approach 1 (OAuth2 Resource Server) is correctly
     * validating incoming Bearer tokens using the JWKS endpoint.
     *
     * @param jwt Injected by Spring Security after JWT validation
     * @return JWT subject, claims, and key ID used for signing
     */
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

    /**
     * Protected: Return greeting confirming JWT authentication is working.
     */
    @GetMapping("/protected/hello")
    public ResponseEntity<Map<String, String>> hello(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(Map.of(
                "message", "Hello, " + jwt.getSubject() + "! Your JWT is valid.",
                "kid", (String) jwt.getHeaders().getOrDefault("kid", "unknown")
        ));
    }
}
