package com.poc.jwkpoc.service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.poc.jwkpoc.entity.KeyRotationAudit;
import com.poc.jwkpoc.exception.JwkException;
import com.poc.jwkpoc.repository.KeyRotationAuditRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for JwkRotationService — PKI key lifecycle management.
 */
@DisplayName("JwkRotationService — Key Lifecycle & Rotation")
@ExtendWith(MockitoExtension.class)
class JwkRotationServiceTest {

    @Mock
    private KeyRotationAuditRepository auditRepository;

    private JwkRotationService rotationService;

    @BeforeEach
    void setUp() {
        when(auditRepository.save(any(KeyRotationAudit.class))).thenAnswer(inv -> inv.getArgument(0));
        rotationService = new JwkRotationService(new JwkService(), auditRepository);
        rotationService.init();
    }

    @Nested
    @DisplayName("Initialisation")
    class InitialisationTests {

        @Test
        @DisplayName("Should generate an initial signing key on startup")
        void shouldGenerateInitialKey() {
            assertThat(rotationService.getActiveKid()).isNotNull().isNotEmpty();
            assertThat(rotationService.getActiveKeyCount()).isEqualTo(1);
        }

        @Test
        @DisplayName("Should publish JWKS after initialisation")
        void shouldPublishJwksOnInit() {
            JWKSet jwkSet = rotationService.getPublicJwkSet();

            assertThat(jwkSet).isNotNull();
            assertThat(jwkSet.getKeys()).hasSize(1);
        }

        @Test
        @DisplayName("Should persist audit record on init")
        void shouldPersistAuditOnInit() {
            ArgumentCaptor<KeyRotationAudit> auditCaptor =
                    ArgumentCaptor.forClass(KeyRotationAudit.class);
            verify(auditRepository, atLeastOnce()).save(auditCaptor.capture());

            KeyRotationAudit saved = auditCaptor.getValue();
            assertThat(saved.getReason()).isEqualTo("startup-init");
            assertThat(saved.isActive()).isTrue();
            assertThat(saved.getAlgorithm()).isEqualTo("RS256");
            assertThat(saved.getKeySize()).isEqualTo(2048);
        }
    }

    @Nested
    @DisplayName("Key Rotation")
    class KeyRotationTests {

        @Test
        @DisplayName("Should generate new kid on rotation")
        void shouldGenerateNewKidOnRotation() {
            String kidBefore = rotationService.getActiveKid();

            rotationService.rotateKey("test-rotation");

            String kidAfter = rotationService.getActiveKid();
            assertThat(kidAfter).isNotEqualTo(kidBefore);
        }

        @Test
        @DisplayName("Should maintain overlap window with 2 keys after first rotation")
        void shouldMaintainTwoKeysAfterRotation() {
            rotationService.rotateKey("first-rotation");

            // Should have 2 keys: old + new (overlap window)
            assertThat(rotationService.getActiveKeyCount()).isEqualTo(2);
        }

        @Test
        @DisplayName("Should cap active keys at MAX_ACTIVE_KEYS=2")
        void shouldCapAtMaxActiveKeys() {
            rotationService.rotateKey("rotation-1");
            rotationService.rotateKey("rotation-2");
            rotationService.rotateKey("rotation-3");

            assertThat(rotationService.getActiveKeyCount()).isLessThanOrEqualTo(2);
        }

        @Test
        @DisplayName("Should include all active keys in published JWKS")
        void shouldIncludeAllActiveKeysInJwks() {
            rotationService.rotateKey("jwks-test");

            JWKSet jwkSet = rotationService.getPublicJwkSet();
            assertThat(jwkSet.getKeys()).hasSize(rotationService.getActiveKeyCount());
        }

        @Test
        @DisplayName("JWKS should contain ONLY public keys after rotation")
        void jwksShouldContainOnlyPublicKeys() {
            rotationService.rotateKey("public-key-test");

            JWKSet jwkSet = rotationService.getPublicJwkSet();
            jwkSet.getKeys().forEach(jwk -> {
                assertThat(jwk.isPrivate()).isFalse();
                if (jwk instanceof RSAKey rsaKey) {
                    assertThat(rsaKey.getPrivateExponent()).isNull();
                }
            });
        }

        @Test
        @DisplayName("Should persist audit record on each rotation")
        void shouldPersistAuditOnRotation() {
            rotationService.rotateKey("audit-test-rotation");

            ArgumentCaptor<KeyRotationAudit> captor =
                    ArgumentCaptor.forClass(KeyRotationAudit.class);
            verify(auditRepository, atLeast(2)).save(captor.capture());

            KeyRotationAudit latest = captor.getAllValues()
                    .stream()
                    .filter(a -> "audit-test-rotation".equals(a.getReason()))
                    .findFirst()
                    .orElseThrow();

            assertThat(latest.isActive()).isTrue();
            assertThat(latest.getCreatedAt()).isNotNull();
        }
    }

    @Nested
    @DisplayName("Current Signing Key")
    class CurrentSigningKeyTests {

        @Test
        @DisplayName("Should return the latest key as the current signing key")
        void shouldReturnLatestKeyForSigning() {
            String kidBefore = rotationService.getActiveKid();
            RSAKey signingKey = rotationService.getCurrentSigningKey();

            assertThat(signingKey.getKeyID()).isEqualTo(kidBefore);
            assertThat(signingKey.isPrivate()).isTrue(); // Must have private key for signing
        }

        @Test
        @DisplayName("Should update active signing kid after rotation")
        void shouldUpdateSigningKidAfterRotation() {
            String kidBefore = rotationService.getActiveKid();
            rotationService.rotateKey("update-kid-test");
            String kidAfter = rotationService.getActiveKid();

            RSAKey currentKey = rotationService.getCurrentSigningKey();
            assertThat(currentKey.getKeyID()).isEqualTo(kidAfter).isNotEqualTo(kidBefore);
        }
    }
}
