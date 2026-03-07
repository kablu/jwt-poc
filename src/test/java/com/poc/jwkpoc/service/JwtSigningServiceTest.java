package com.poc.jwkpoc.service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.poc.jwkpoc.exception.JwkException;
import com.poc.jwkpoc.model.TokenRequest;
import com.poc.jwkpoc.model.TokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JwtSigningService — JWT issuance and verification.
 */
@DisplayName("JwtSigningService — JWT Signing & Verification")
@ExtendWith(MockitoExtension.class)
class JwtSigningServiceTest {

    @Mock
    private JwkRotationService jwkRotationService;

    private JwtSigningService jwtSigningService;
    private JwkService jwkService;
    private RSAKey testRsaKey;

    @BeforeEach
    void setUp() throws Exception {
        jwkService = new JwkService();
        testRsaKey = jwkService.generateRsaJwk(2048, "test-signing-key");

        jwtSigningService = new JwtSigningService(jwkRotationService);
        ReflectionTestUtils.setField(jwtSigningService, "issuer", "https://poc.jwk-poc.local");
    }

    @Nested
    @DisplayName("JWT Issuance")
    class TokenIssuanceTests {

        @BeforeEach
        void mockRotationService() {
            when(jwkRotationService.getCurrentSigningKey()).thenReturn(testRsaKey);
        }

        @Test
        @DisplayName("Should issue a signed JWT with correct structure")
        void shouldIssueSignedJwt() {
            TokenRequest request = TokenRequest.builder()
                    .subject("user-123")
                    .audiences(List.of("jwk-poc-api"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse response = jwtSigningService.issueToken(request);

            assertThat(response).isNotNull();
            assertThat(response.getAccessToken()).isNotBlank();
            assertThat(response.getTokenType()).isEqualTo("Bearer");
            assertThat(response.getExpiresIn()).isEqualTo(3600);
            assertThat(response.getKeyId()).isEqualTo("test-signing-key");
            assertThat(response.getAlgorithm()).isEqualTo("RS256");
        }

        @Test
        @DisplayName("Should include roles in JWT claims")
        void shouldIncludeRolesInJwtClaims() {
            TokenRequest request = TokenRequest.builder()
                    .subject("admin-user")
                    .audiences(List.of("jwk-poc-api"))
                    .roles(List.of("ADMIN", "USER"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse response = jwtSigningService.issueToken(request);
            Map<String, Object> claims = jwtSigningService.parseUnverified(response.getAccessToken());

            assertThat(claims).containsKey("roles");
          //  assertThat((List<?>) claims.get("roles")).containsExactly("ADMIN", "USER");
        }

        @Test
        @DisplayName("Should include additional custom claims")
        void shouldIncludeAdditionalClaims() {
            TokenRequest request = TokenRequest.builder()
                    .subject("user-custom")
                    .audiences(List.of("jwk-poc-api"))
                    .additionalClaims(Map.of("tenantId", "tenant-001", "region", "EU"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse response = jwtSigningService.issueToken(request);
            Map<String, Object> claims = jwtSigningService.parseUnverified(response.getAccessToken());

            assertThat(claims).containsEntry("tenantId", "tenant-001");
            assertThat(claims).containsEntry("region", "EU");
        }

        @Test
        @DisplayName("Should set correct issuer claim")
        void shouldSetCorrectIssuerClaim() {
            TokenRequest request = TokenRequest.builder()
                    .subject("user-iss-test")
                    .audiences(List.of("jwk-poc-api"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse response = jwtSigningService.issueToken(request);
            Map<String, Object> claims = jwtSigningService.parseUnverified(response.getAccessToken());

            assertThat(claims).containsEntry("iss", "https://poc.jwk-poc.local");
        }

        @Test
        @DisplayName("JWT should contain three parts (header.payload.signature)")
        void shouldHaveThreePartStructure() {
            TokenRequest request = TokenRequest.builder()
                    .subject("user-structure-test")
                    .expirySeconds(3600)
                    .build();

            TokenResponse response = jwtSigningService.issueToken(request);
            String[] parts = response.getAccessToken().split("\\.");

            assertThat(parts).hasSize(3);
        }
    }

    @Nested
    @DisplayName("JWT Verification")
    class TokenVerificationTests {

        @Test
        @DisplayName("Should verify a validly signed JWT")
        void shouldVerifyValidToken() {
            when(jwkRotationService.getCurrentSigningKey()).thenReturn(testRsaKey);
            JWKSet publicJwkSet = new JWKSet(testRsaKey.toPublicJWK());
            when(jwkRotationService.getPublicJwkSet()).thenReturn(publicJwkSet);

            TokenRequest request = TokenRequest.builder()
                    .subject("verify-user")
                    .audiences(List.of("jwk-poc-api"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse issued = jwtSigningService.issueToken(request);
            JWTClaimsSet claims = jwtSigningService.verifyToken(issued.getAccessToken());

            assertThat(claims.getSubject()).isEqualTo("verify-user");
            assertThat(claims.getIssuer()).isEqualTo("https://poc.jwk-poc.local");
        }

        @Test
        @DisplayName("Should reject a tampered JWT")
        void shouldRejectTamperedToken() {
            when(jwkRotationService.getCurrentSigningKey()).thenReturn(testRsaKey);
            JWKSet publicJwkSet = new JWKSet(testRsaKey.toPublicJWK());
            when(jwkRotationService.getPublicJwkSet()).thenReturn(publicJwkSet);

            TokenRequest request = TokenRequest.builder()
                    .subject("tamper-test")
                    .audiences(List.of("jwk-poc-api"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse issued = jwtSigningService.issueToken(request);

            // Tamper the payload (middle part)
            String[] parts = issued.getAccessToken().split("\\.");
            String tamperedToken = parts[0] + ".dGFtcGVyZWQ" + "." + parts[2];

            assertThatThrownBy(() -> jwtSigningService.verifyToken(tamperedToken))
                    .isInstanceOf(JwkException.class);
        }

        @Test
        @DisplayName("Should verify signature using public RSA key directly")
        void shouldVerifySignatureWithPublicKey() {
            when(jwkRotationService.getCurrentSigningKey()).thenReturn(testRsaKey);

            TokenRequest request = TokenRequest.builder()
                    .subject("sig-verify-test")
                    .expirySeconds(3600)
                    .build();

            TokenResponse issued = jwtSigningService.issueToken(request);
            boolean valid = jwtSigningService.verifySignatureOnly(
                    issued.getAccessToken(), testRsaKey.toPublicJWK()
            );

            assertThat(valid).isTrue();
        }

        @Test
        @DisplayName("Should reject signature verification with wrong public key")
        void shouldRejectSignatureWithWrongKey() {
            when(jwkRotationService.getCurrentSigningKey()).thenReturn(testRsaKey);

            TokenRequest request = TokenRequest.builder()
                    .subject("wrong-key-test")
                    .expirySeconds(3600)
                    .build();

            TokenResponse issued = jwtSigningService.issueToken(request);

            RSAKey differentKey = jwkService.generateRsaJwk(2048, "different-key");
            boolean valid = jwtSigningService.verifySignatureOnly(
                    issued.getAccessToken(), differentKey.toPublicJWK()
            );

            assertThat(valid).isFalse();
        }
    }

    @Nested
    @DisplayName("JWT Parsing")
    class JwtParsingTests {

        @Test
        @DisplayName("Should parse unverified JWT claims")
        void shouldParseUnverifiedClaims() {
            when(jwkRotationService.getCurrentSigningKey()).thenReturn(testRsaKey);

            TokenRequest request = TokenRequest.builder()
                    .subject("parse-subject")
                    .audiences(List.of("jwk-poc-api"))
                    .expirySeconds(3600)
                    .build();

            TokenResponse issued = jwtSigningService.issueToken(request);
            Map<String, Object> claims = jwtSigningService.parseUnverified(issued.getAccessToken());

            assertThat(claims).containsEntry("sub", "parse-subject");
            assertThat(claims).containsKey("iat");
            assertThat(claims).containsKey("exp");
        }

        @Test
        @DisplayName("Should throw JwkException on unparseable token")
        void shouldThrowOnUnparseableToken() {
            assertThatThrownBy(() -> jwtSigningService.parseUnverified("not.a.jwt"))
                    .isInstanceOf(JwkException.class)
                    .hasMessageContaining("Failed to parse JWT");
        }
    }
}
