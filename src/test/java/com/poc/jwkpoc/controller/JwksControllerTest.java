package com.poc.jwkpoc.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.poc.jwkpoc.repository.KeyRotationAuditRepository;
import com.poc.jwkpoc.service.JwkRotationService;
import com.poc.jwkpoc.service.JwkService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Web layer tests for JwksController — JWKS endpoint and admin operations.
 */
@WebMvcTest(JwksController.class)
@DisplayName("JwksController — JWKS Endpoint & Admin Operations")
class JwksControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwkRotationService jwkRotationService;

    @MockBean
    private KeyRotationAuditRepository auditRepository;

    private RSAKey testRsaKey;
    private JWKSet testPublicJwkSet;

    @BeforeEach
    void setUp() {
        JwkService jwkService = new JwkService();
        testRsaKey = jwkService.generateRsaJwk(2048, "test-jwks-key");
        testPublicJwkSet = new JWKSet(testRsaKey.toPublicJWK());

        when(jwkRotationService.getPublicJwkSet()).thenReturn(testPublicJwkSet);
        when(jwkRotationService.getActiveKid()).thenReturn("test-jwks-key");
        when(jwkRotationService.getActiveKeyCount()).thenReturn(1);
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json — should return JWKS with public keys (no auth required)")
    void shouldReturnJwksWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].kid").value("test-jwks-key"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json — should NOT expose private key parameters")
    void shouldNotExposePrivateKeyInJwks() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())   // private exponent
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())   // first prime
                .andExpect(jsonPath("$.keys[0].q").doesNotExist())   // second prime
                .andExpect(jsonPath("$.keys[0].dp").doesNotExist())  // CRT exponent
                .andExpect(jsonPath("$.keys[0].dq").doesNotExist())  // CRT exponent
                .andExpect(jsonPath("$.keys[0].qi").doesNotExist()); // CRT coefficient
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json — should set Cache-Control header")
    void shouldSetCacheControlHeader() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=3600"));
    }

    @Test
    @DisplayName("GET /.well-known/openid-configuration — should return OIDC metadata (no auth required)")
    void shouldReturnOidcDiscovery() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").isNotEmpty())
                .andExpect(jsonPath("$.jwks_uri").isNotEmpty())
                .andExpect(jsonPath("$.token_endpoint").isNotEmpty());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("POST /api/admin/keys/rotate — should trigger rotation with ADMIN role")
    void shouldTriggerRotationWithAdminRole() throws Exception {
        mockMvc.perform(post("/api/admin/keys/rotate")
                        .param("reason", "test-manual-rotation"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("rotated"))
                .andExpect(jsonPath("$.activeKid").value("test-jwks-key"));

        verify(jwkRotationService).rotateKey("test-manual-rotation");
    }

    @Test
    @DisplayName("POST /api/admin/keys/rotate — should reject unauthenticated request")
    void shouldRejectRotationWithoutAuth() throws Exception {
        mockMvc.perform(post("/api/admin/keys/rotate"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(roles = "USER")
    @DisplayName("POST /api/admin/keys/rotate — should reject USER role (forbidden)")
    void shouldRejectRotationWithUserRole() throws Exception {
        mockMvc.perform(post("/api/admin/keys/rotate"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("GET /api/admin/keys/audit — should return audit log with ADMIN role")
    void shouldReturnAuditLogWithAdminRole() throws Exception {
        when(auditRepository.findAllByOrderByCreatedAtDesc()).thenReturn(List.of());

        mockMvc.perform(get("/api/admin/keys/audit"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON));
    }

    @Test
    @WithMockUser(roles = "ADMIN")
    @DisplayName("GET /api/admin/keys/active — should return active key info")
    void shouldReturnActiveKeyInfo() throws Exception {
        mockMvc.perform(get("/api/admin/keys/active"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.activeKid").value("test-jwks-key"))
                .andExpect(jsonPath("$.activeKeyCount").value(1));
    }
}
