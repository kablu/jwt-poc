package com.poc.authserver.controller;

import com.poc.authserver.service.KeyPairRegistryService;
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
import java.util.Map;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Web layer tests for JwksController.
 */
@WebMvcTest(JwksController.class)
@DisplayName("JwksController — JWKS Endpoint Tests")
class JwksControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private KeyPairRegistryService keyPairRegistryService;

    private KeyPairRegistryService realService;

    @BeforeEach
    void setUp() {
        realService = new KeyPairRegistryService();
        realService.generateAllKeyPairs();

        when(keyPairRegistryService.getPublicJwkSet()).thenReturn(realService.getPublicJwkSet());
        when(keyPairRegistryService.getTotalKeyCount()).thenReturn(10);
        when(keyPairRegistryService.getKeyMetadata()).thenReturn(realService.getKeyMetadata());
    }

    @Test
    @DisplayName("GET /.well-known/jwks.json — should return 200 with 10 keys (no auth required)")
    void shouldReturnJwksWithoutAuthentication() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(10))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
    }

    @Test
    @DisplayName("JWKS must NOT expose any private key parameters (d, p, q, dp, dq, qi)")
    void shouldNeverExposePrivateKeyParameters() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dp").doesNotExist())
                .andExpect(jsonPath("$.keys[0].dq").doesNotExist())
                .andExpect(jsonPath("$.keys[0].qi").doesNotExist());
    }

    @Test
    @DisplayName("JWKS should contain Cache-Control header")
    void shouldSetCacheControlHeader() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "public, max-age=3600"));
    }

    @Test
    @DisplayName("JWKS keys should have kids auth-server-key-01 to auth-server-key-10")
    void shouldHaveCorrectKidNaming() throws Exception {
        for (int i = 1; i <= 10; i++) {
            String expectedKid = String.format("auth-server-key-%02d", i);
            mockMvc.perform(get("/.well-known/jwks.json"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath(
                        "$.keys[?(@.kid=='" + expectedKid + "')]").isNotEmpty()
                    );
        }
    }

    @Test
    @DisplayName("GET /api/keys/info — should return key metadata without key material")
    @WithMockUser
    void shouldReturnKeyInfoWithoutKeyMaterial() throws Exception {
        mockMvc.perform(get("/api/keys/info"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalKeyPairs").value(10))
                .andExpect(jsonPath("$.algorithm").value("RS256"))
                .andExpect(jsonPath("$.keySize").value("RSA-2048"))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(10));
    }
}
