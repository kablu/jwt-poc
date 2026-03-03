package com.poc.jwkpoc.validator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for AudienceValidator — RFC 7519 §4.1.3 audience claim validation.
 */
@DisplayName("AudienceValidator — RFC 7519 Audience Claim Validation")
class AudienceValidatorTest {

    private AudienceValidator audienceValidator;

    @BeforeEach
    void setUp() {
        audienceValidator = new AudienceValidator(List.of("jwk-poc-api", "admin-api"));
    }

    @Test
    @DisplayName("Should accept JWT with matching audience")
    void shouldAcceptJwtWithMatchingAudience() {
        Jwt jwt = buildJwt(List.of("jwk-poc-api"));

        OAuth2TokenValidatorResult result = audienceValidator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("Should accept JWT when one of multiple audiences matches")
    void shouldAcceptWhenOneAudienceMatches() {
        Jwt jwt = buildJwt(List.of("other-api", "jwk-poc-api", "yet-another-api"));

        OAuth2TokenValidatorResult result = audienceValidator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("Should accept JWT with second required audience")
    void shouldAcceptJwtWithSecondRequiredAudience() {
        Jwt jwt = buildJwt(List.of("admin-api"));

        OAuth2TokenValidatorResult result = audienceValidator.validate(jwt);

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    @DisplayName("Should reject JWT with no matching audience")
    void shouldRejectJwtWithNoMatchingAudience() {
        Jwt jwt = buildJwt(List.of("wrong-api", "another-wrong-api"));

        OAuth2TokenValidatorResult result = audienceValidator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .extracting("errorCode")
                .containsOnly("invalid_token");
    }

    @Test
    @DisplayName("Should reject JWT with null audience claim")
    void shouldRejectJwtWithNullAudience() {
        Jwt jwt = buildJwt(null);

        OAuth2TokenValidatorResult result = audienceValidator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    @DisplayName("Should reject JWT with empty audience claim")
    void shouldRejectJwtWithEmptyAudience() {
        Jwt jwt = buildJwt(List.of());

        OAuth2TokenValidatorResult result = audienceValidator.validate(jwt);

        assertThat(result.hasErrors()).isTrue();
    }

    // --- Helpers ---

    private Jwt buildJwt(List<String> audiences) {
        Map<String, Object> headers = Map.of("alg", "RS256", "kid", "test-kid");
        Map<String, Object> claims = new java.util.HashMap<>();
        claims.put("sub", "test-user");
        claims.put("iss", "https://poc.jwk-poc.local");
        if (audiences != null) {
            claims.put("aud", audiences);
        }

        return new Jwt(
                "token-value",
                Instant.now(),
                Instant.now().plusSeconds(3600),
                headers,
                claims
        );
    }
}
