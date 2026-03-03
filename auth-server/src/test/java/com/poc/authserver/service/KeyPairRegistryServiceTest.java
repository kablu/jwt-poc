package com.poc.authserver.service;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for KeyPairRegistryService — 10 RSA key pair generation.
 */
@DisplayName("KeyPairRegistryService — 10 RSA Key Pair Management")
class KeyPairRegistryServiceTest {

    private KeyPairRegistryService keyPairRegistryService;

    @BeforeEach
    void setUp() {
        keyPairRegistryService = new KeyPairRegistryService();
        keyPairRegistryService.generateAllKeyPairs(); // @PostConstruct manually triggered
    }

    @Nested
    @DisplayName("Key Generation")
    class KeyGenerationTests {

        @Test
        @DisplayName("Should generate exactly 10 RSA key pairs")
        void shouldGenerateExactlyTenKeyPairs() {
            assertThat(keyPairRegistryService.getTotalKeyCount()).isEqualTo(10);
        }

        @Test
        @DisplayName("Each key pair should have a unique kid")
        void shouldHaveUniqueKids() {
            List<RSAKey> keys = keyPairRegistryService.getAllFullKeyPairs();
            Set<String> kids = keys.stream().map(RSAKey::getKeyID).collect(Collectors.toSet());

            assertThat(kids).hasSize(10); // All unique
        }

        @Test
        @DisplayName("Kids should follow naming convention auth-server-key-01 to auth-server-key-10")
        void shouldFollowKidNamingConvention() {
            List<RSAKey> keys = keyPairRegistryService.getAllFullKeyPairs();

            for (int i = 1; i <= 10; i++) {
                String expectedKid = String.format("auth-server-key-%02d", i);
                assertThat(keys.stream().anyMatch(k -> k.getKeyID().equals(expectedKid)))
                        .as("Expected kid: " + expectedKid)
                        .isTrue();
            }
        }

        @Test
        @DisplayName("All key pairs should be RSA-2048")
        void shouldBeRsa2048() {
            keyPairRegistryService.getAllFullKeyPairs().forEach(rsaKey -> {
                assertThat(rsaKey.toRSAPublicKey().getModulus().bitLength())
                        .as("Key %s should be 2048-bit", rsaKey.getKeyID())
                        .isEqualTo(2048);
            });
        }

        @Test
        @DisplayName("All key pairs should contain private key material")
        void shouldContainPrivateKeyMaterial() {
            keyPairRegistryService.getAllFullKeyPairs().forEach(rsaKey -> {
                assertThat(rsaKey.isPrivate())
                        .as("Key %s should have private key", rsaKey.getKeyID())
                        .isTrue();
                assertThat(rsaKey.getPrivateExponent())
                        .as("Private exponent (d) should be present for %s", rsaKey.getKeyID())
                        .isNotNull();
            });
        }
    }

    @Nested
    @DisplayName("Public JWKS")
    class PublicJwksTests {

        @Test
        @DisplayName("Public JWKSet should contain exactly 10 keys")
        void shouldContainTenPublicKeys() {
            JWKSet publicJwkSet = keyPairRegistryService.getPublicJwkSet();
            assertThat(publicJwkSet.getKeys()).hasSize(10);
        }

        @Test
        @DisplayName("Public JWKSet must NOT expose any private key material")
        void shouldNotExposePrivateKeyMaterial() {
            JWKSet publicJwkSet = keyPairRegistryService.getPublicJwkSet();

            publicJwkSet.getKeys().forEach(jwk -> {
                assertThat(jwk.isPrivate())
                        .as("Key %s must NOT have private key in public JWKS", jwk.getKeyID())
                        .isFalse();

                RSAKey rsaKey = (RSAKey) jwk;
                assertThat(rsaKey.getPrivateExponent()).isNull();   // d must be absent
                assertThat(rsaKey.getFirstPrimeFactor()).isNull();  // p must be absent
                assertThat(rsaKey.getSecondPrimeFactor()).isNull(); // q must be absent
                assertThat(rsaKey.getFirstFactorCRTExponent()).isNull();  // dp
                assertThat(rsaKey.getSecondFactorCRTExponent()).isNull(); // dq
                assertThat(rsaKey.getFirstCRTCoefficient()).isNull();     // qi
            });
        }

        @Test
        @DisplayName("Public JWKSet should contain n and e parameters")
        void shouldContainPublicKeyParameters() {
            JWKSet publicJwkSet = keyPairRegistryService.getPublicJwkSet();

            publicJwkSet.getKeys().forEach(jwk -> {
                RSAKey rsaKey = (RSAKey) jwk;
                assertThat(rsaKey.getModulus()).isNotNull();       // n (modulus) — required
                assertThat(rsaKey.getPublicExponent()).isNotNull();// e (exponent) — required
            });
        }

        @Test
        @DisplayName("Full JWKSet should contain all private key material (internal use only)")
        void fullJwkSetShouldContainPrivateKeys() {
            JWKSet fullJwkSet = keyPairRegistryService.getFullJwkSet();

            fullJwkSet.getKeys().forEach(jwk -> {
                RSAKey rsaKey = (RSAKey) jwk;
                assertThat(rsaKey.isPrivate()).isTrue();
                assertThat(rsaKey.getPrivateExponent()).isNotNull();
            });
        }
    }

    @Nested
    @DisplayName("Key Metadata")
    class KeyMetadataTests {

        @Test
        @DisplayName("getKeyMetadata should return 10 entries")
        void shouldReturnTenMetadataEntries() {
            List<Map<String, String>> metadata = keyPairRegistryService.getKeyMetadata();
            assertThat(metadata).hasSize(10);
        }

        @Test
        @DisplayName("Metadata should NOT contain any key material")
        void metadataShouldNotContainKeyMaterial() {
            keyPairRegistryService.getKeyMetadata().forEach(meta -> {
                assertThat(meta).doesNotContainKey("n");
                assertThat(meta).doesNotContainKey("e");
                assertThat(meta).doesNotContainKey("d");
                assertThat(meta).containsKey("kid");
                assertThat(meta).containsKey("algorithm");
            });
        }

        @Test
        @DisplayName("All keys should have RS256 algorithm")
        void shouldUseRS256Algorithm() {
            keyPairRegistryService.getKeyMetadata().forEach(meta ->
                    assertThat(meta.get("algorithm")).isEqualTo("RS256")
            );
        }
    }
}
