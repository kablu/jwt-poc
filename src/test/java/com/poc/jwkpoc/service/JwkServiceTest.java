package com.poc.jwkpoc.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.poc.jwkpoc.exception.JwkException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for JwkService — RFC 7517 JWK generation and parsing.
 */
@DisplayName("JwkService — RFC 7517 JWK Key Generation")
class JwkServiceTest {

    private JwkService jwkService;

    @BeforeEach
    void setUp() {
        jwkService = new JwkService();
    }

    @Nested
    @DisplayName("RSA Key Generation")
    class RsaKeyGenerationTests {

        @Test
        @DisplayName("Should generate RSA-2048 JWK with all required parameters")
        void shouldGenerateRsa2048Jwk() {
            RSAKey rsaKey = jwkService.generateRsaJwk(2048, "test-kid-001");

            assertThat(rsaKey).isNotNull();
            assertThat(rsaKey.getKeyID()).isEqualTo("test-kid-001");
            assertThat(rsaKey.getKeyUse()).isEqualTo(KeyUse.SIGNATURE);
            assertThat(rsaKey.getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
            assertThat(rsaKey.getModulus()).isNotNull();          // n
            assertThat(rsaKey.getPublicExponent()).isNotNull();   // e
            assertThat(rsaKey.getPrivateExponent()).isNotNull();  // d (private)
        }

        @ParameterizedTest(name = "RSA key size {0} bits")
        @ValueSource(ints = {2048, 3072, 4096})
        @DisplayName("Should generate RSA JWK for valid key sizes")
        void shouldGenerateRsaJwkForValidKeySizes(int keySize) {
            RSAKey rsaKey = jwkService.generateRsaJwk(keySize, null);

            assertThat(rsaKey).isNotNull();
            assertThat(rsaKey.getKeyID()).isNotNull().isNotEmpty(); // Auto-generated UUID
        }

        @Test
        @DisplayName("Should auto-generate kid UUID when kid is null")
        void shouldAutoGenerateKidWhenNull() {
            RSAKey key1 = jwkService.generateRsaJwk(2048, null);
            RSAKey key2 = jwkService.generateRsaJwk(2048, null);

            assertThat(key1.getKeyID()).isNotNull();
            assertThat(key2.getKeyID()).isNotNull();
            assertThat(key1.getKeyID()).isNotEqualTo(key2.getKeyID()); // Each is unique
        }

        @Test
        @DisplayName("Should reject RSA key size below 2048 bits (NIST requirement)")
        void shouldRejectSmallRsaKeySize() {
            assertThatThrownBy(() -> jwkService.generateRsaJwk(1024, "small-key"))
                    .isInstanceOf(JwkException.class)
                    .hasMessageContaining("2048 bits");
        }

        @Test
        @DisplayName("Should generate RSA JWK with private key material")
        void shouldContainPrivateKeyMaterial() {
            RSAKey rsaKey = jwkService.generateRsaJwk(2048, "private-key-test");

            assertThat(rsaKey.isPrivate()).isTrue();
            assertThat(rsaKey.getPrivateExponent()).isNotNull();
        }
    }

    @Nested
    @DisplayName("EC Key Generation")
    class EcKeyGenerationTests {

        @Test
        @DisplayName("Should generate P-256 EC JWK with ES256 algorithm")
        void shouldGenerateP256EcJwk() {
            ECKey ecKey = jwkService.generateEcJwk(Curve.P_256, "ec-key-001");

            assertThat(ecKey).isNotNull();
            assertThat(ecKey.getKeyID()).isEqualTo("ec-key-001");
            assertThat(ecKey.getCurve()).isEqualTo(Curve.P_256);
            assertThat(ecKey.getAlgorithm()).isEqualTo(JWSAlgorithm.ES256);
            assertThat(ecKey.getX()).isNotNull();
            assertThat(ecKey.getY()).isNotNull();
        }

        @Test
        @DisplayName("Should generate P-384 EC JWK with ES384 algorithm")
        void shouldGenerateP384EcJwk() {
            ECKey ecKey = jwkService.generateEcJwk(Curve.P_384, "ec-key-384");

            assertThat(ecKey.getCurve()).isEqualTo(Curve.P_384);
            assertThat(ecKey.getAlgorithm()).isEqualTo(JWSAlgorithm.ES384);
        }

        @Test
        @DisplayName("Should generate P-521 EC JWK with ES512 algorithm")
        void shouldGenerateP521EcJwk() {
            ECKey ecKey = jwkService.generateEcJwk(Curve.P_521, "ec-key-521");

            assertThat(ecKey.getCurve()).isEqualTo(Curve.P_521);
            assertThat(ecKey.getAlgorithm()).isEqualTo(JWSAlgorithm.ES512);
        }
    }

    @Nested
    @DisplayName("KeyPair Conversion")
    class KeyPairConversionTests {

        @Test
        @DisplayName("Should convert Java RSA KeyPair to JWK")
        void shouldConvertKeyPairToJwk() throws Exception {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();

            RSAKey rsaKey = jwkService.fromKeyPair(keyPair, "converted-key");

            assertThat(rsaKey.getKeyID()).isEqualTo("converted-key");
            assertThat(rsaKey.toRSAPublicKey()).isEqualTo(keyPair.getPublic());
            assertThat(rsaKey.toRSAPrivateKey()).isEqualTo(keyPair.getPrivate());
        }
    }

    @Nested
    @DisplayName("Public Key Extraction")
    class PublicKeyExtractionTests {

        @Test
        @DisplayName("Should strip private key material from RSA JWK")
        void shouldStripPrivateKeyMaterial() {
            RSAKey fullKey = jwkService.generateRsaJwk(2048, "full-key");
            RSAKey publicKey = jwkService.toPublicJwk(fullKey);

            assertThat(fullKey.isPrivate()).isTrue();
            assertThat(publicKey.isPrivate()).isFalse();
            assertThat(publicKey.getPrivateExponent()).isNull();  // d must be absent
            assertThat(publicKey.getModulus()).isNotNull();        // n must be present
            assertThat(publicKey.getPublicExponent()).isNotNull(); // e must be present
        }
    }

    @Nested
    @DisplayName("JWK Parsing")
    class JwkParsingTests {

        @Test
        @DisplayName("Should parse valid RSA JWK JSON")
        void shouldParseValidRsaJwkJson() {
            RSAKey original = jwkService.generateRsaJwk(2048, "parse-test");
            String jwkJson = original.toPublicJWK().toJSONString();

            JWK parsed = jwkService.parseJwk(jwkJson);

            assertThat(parsed).isNotNull();
            assertThat(parsed.getKeyID()).isEqualTo("parse-test");
            assertThat(parsed.getKeyType()).isEqualTo(KeyType.RSA);
        }

        @Test
        @DisplayName("Should throw JwkException on invalid JWK JSON")
        void shouldThrowOnInvalidJson() {
            assertThatThrownBy(() -> jwkService.parseJwk("not-valid-json"))
                    .isInstanceOf(JwkException.class)
                    .hasMessageContaining("Failed to parse JWK");
        }

        @Test
        @DisplayName("Should parse valid JWKS JSON")
        void shouldParseValidJwksJson() {
            RSAKey key1 = jwkService.generateRsaJwk(2048, "jwks-key-1");
            RSAKey key2 = jwkService.generateRsaJwk(2048, "jwks-key-2");
            JWKSet jwkSet = new JWKSet(java.util.List.of(
                    key1.toPublicJWK(), key2.toPublicJWK()
            ));
            String jwksJson = jwkSet.toString();

            JWKSet parsed = jwkService.parseJwkSet(jwksJson);

            assertThat(parsed.getKeys()).hasSize(2);
        }
    }
}
