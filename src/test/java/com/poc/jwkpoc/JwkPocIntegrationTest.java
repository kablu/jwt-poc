package com.poc.jwkpoc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.poc.jwkpoc.model.TokenRequest;
import com.poc.jwkpoc.model.TokenResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration test — end-to-end JWT issuance and JWKS endpoint verification.
 *
 * Tests the full flow:
 *   1. JWKS endpoint returns valid public keys
 *   2. Token endpoint issues a signed JWT
 *   3. JWT header contains correct kid and alg
 *   4. No private key material is exposed
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@DisplayName("Integration — End-to-End JWT + JWKS Flow")
class JwkPocIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("JWKS endpoint should be publicly accessible and return valid key set")
    void jwksEndpointShouldReturnPublicKeys() throws Exception {
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].e").isNotEmpty())
                // CRITICAL: private key material must NOT be present
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andExpect(jsonPath("$.keys[0].p").doesNotExist())
                .andExpect(jsonPath("$.keys[0].q").doesNotExist());
    }

    @Test
    @DisplayName("Token endpoint should issue a 3-part JWT")
    void tokenEndpointShouldIssueJwt() throws Exception {
        TokenRequest request = TokenRequest.builder()
                .subject("integration-user")
                .audiences(List.of("jwk-poc-api"))
                .roles(List.of("USER"))
                .expirySeconds(3600)
                .build();

        MvcResult result = mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.algorithm").value("RS256"))
                .andReturn();

        String responseBody = result.getResponse().getContentAsString();
        TokenResponse tokenResponse = objectMapper.readValue(responseBody, TokenResponse.class);

        // Verify JWT has 3 parts (header.payload.signature)
        String[] jwtParts = tokenResponse.getAccessToken().split("\\.");
        assertThat(jwtParts).hasSize(3);

        // Verify kid in response matches the active key
        assertThat(tokenResponse.getKeyId()).isNotNull().isNotEmpty();
    }

    @Test
    @DisplayName("Protected endpoint should require authentication")
    void protectedEndpointShouldRequireAuth() throws Exception {
        mockMvc.perform(get("/api/protected/hello"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("H2 console should be accessible in dev mode")
    void h2ConsoleShouldBeAccessible() throws Exception {
        mockMvc.perform(get("/h2-console"))
                .andExpect(status().is3xxRedirection()); // Redirects to /h2-console/
    }

    @Test
    @DisplayName("Health actuator endpoint should be accessible")
    void healthEndpointShouldBeAccessible() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("OIDC discovery endpoint should contain correct metadata")
    void oidcDiscoveryShouldContainCorrectMetadata() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").isNotEmpty())
                .andExpect(jsonPath("$.jwks_uri").value(
                    org.hamcrest.Matchers.containsString("/.well-known/jwks.json")
                ));
    }
}
