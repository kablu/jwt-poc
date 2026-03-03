package com.poc.jwkpoc.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.poc.jwkpoc.model.TokenRequest;
import com.poc.jwkpoc.model.TokenResponse;
import com.poc.jwkpoc.service.JwtSigningService;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Web layer tests for TokenController — JWT issuance and protected endpoints.
 */
@WebMvcTest(TokenController.class)
@DisplayName("TokenController — Token Issuance & Protected Endpoints")
class TokenControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private JwtSigningService jwtSigningService;

    @Test
    @DisplayName("POST /api/auth/token — should issue token without authentication")
    void shouldIssueTokenWithoutAuthentication() throws Exception {
        TokenResponse mockResponse = TokenResponse.builder()
                .accessToken("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature")
                .tokenType("Bearer")
                .expiresIn(3600)
                .keyId("test-key")
                .algorithm("RS256")
                .build();

        when(jwtSigningService.issueToken(any(TokenRequest.class))).thenReturn(mockResponse);

        TokenRequest request = TokenRequest.builder()
                .subject("test-user")
                .audiences(List.of("jwk-poc-api"))
                .expirySeconds(3600)
                .build();

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andExpect(jsonPath("$.algorithm").value("RS256"));
    }

    @Test
    @DisplayName("POST /api/auth/token — should reject request with missing subject")
    void shouldRejectMissingSubject() throws Exception {
        TokenRequest invalidRequest = TokenRequest.builder()
                .subject("") // blank subject
                .expirySeconds(3600)
                .build();

        mockMvc.perform(post("/api/auth/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(invalidRequest))
                        .with(csrf()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("GET /api/protected/hello — should reject unauthenticated request")
    void shouldRejectUnauthenticatedProtectedRequest() throws Exception {
        mockMvc.perform(get("/api/protected/hello"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = "test-user")
    @DisplayName("GET /api/protected/hello — should return greeting for authenticated user")
    void shouldReturnGreetingForAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/protected/hello"))
                .andExpect(status().isOk());
    }

    @Test
    @DisplayName("POST /api/auth/verify — should return error for missing token field")
    void shouldReturnErrorForMissingTokenField() throws Exception {
        mockMvc.perform(post("/api/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}")
                        .with(csrf()))
                .andExpect(status().isUnauthorized()); // Protected endpoint
    }

    @Test
    @WithMockUser(username = "test-user")
    @DisplayName("POST /api/auth/verify — should handle blank token gracefully")
    void shouldHandleBlankToken() throws Exception {
        mockMvc.perform(post("/api/auth/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("token", "")))
                        .with(csrf()))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("token field is required"));
    }
}
