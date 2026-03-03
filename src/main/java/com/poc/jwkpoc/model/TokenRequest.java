package com.poc.jwkpoc.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

/**
 * Request payload for JWT token issuance.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenRequest {

    @NotBlank(message = "Subject is required")
    private String subject;

    private List<String> audiences;

    private List<String> roles;

    private Map<String, Object> additionalClaims;

    /** Token validity in seconds. Defaults to 3600 (1 hour). */
    private long expirySeconds = 3600L;
}
