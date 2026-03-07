package com.poc.jwkpoc.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.poc.jwkpoc.exception.JwkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.UUID;

/**
 * Core PKI service responsible for JWK key generation, parsing and conversion.
 *
 * Implements RFC 7517 — JSON Web Key specification.
 * Corresponds to Nimbus JOSE + JWT manual control (Approach 2).
 */
@Service
public class JwkService {

    private static final Logger log = LoggerFactory.getLogger(JwkService.class);

    /**
     * Generate an RSA JWK with the specified key size.
     * Minimum recommended size: 2048 bits (NIST SP 800-131A).
     *
     * @param keySize RSA key size in bits (2048, 3072, 4096)
     * @param kid     Optional key ID; auto-generated UUID if null
     * @return RSAKey containing both public and private key material
     */
    public RSAKey generateRsaJwk(int keySize, String kid) {
        validateRsaKeySize(keySize);
        try {
            RSAKey rsaKey = new RSAKeyGenerator(keySize)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(kid != null ? kid : UUID.randomUUID().toString())
                    .generate();
            log.info("Generated RSA-{} JWK with kid={}", keySize, rsaKey.getKeyID());
            return rsaKey;
        } catch (JOSEException e) {
            throw new JwkException("Failed to generate RSA JWK with size " + keySize, e);
        }
    }

    /**
     * Generate an Elliptic Curve JWK.
     * Curve P-256 provides ~128-bit security level (equivalent to RSA-3072).
     *
     * @param curve EC curve (P-256, P-384, P-521)
     * @param kid   Optional key ID
     * @return ECKey containing both public and private key material
     */
    public ECKey generateEcJwk(Curve curve, String kid) {
        try {
            JWSAlgorithm algorithm = resolveEcAlgorithm(curve);
            ECKey ecKey = new ECKeyGenerator(curve)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(algorithm)
                    .keyID(kid != null ? kid : UUID.randomUUID().toString())
                    .generate();
            log.info("Generated EC JWK curve={} with kid={}", curve.getName(), ecKey.getKeyID());
            return ecKey;
        } catch (JOSEException e) {
            throw new JwkException("Failed to generate EC JWK for curve " + curve.getName(), e);
        }
    }

    /**
     * Convert an existing Java KeyPair to a Nimbus RSAKey JWK.
     * Useful when loading keys from a KeyStore or HSM.
     *
     * @param keyPair Java security KeyPair (must be RSA)
     * @param kid     Key identifier
     * @return RSAKey JWK representation
     */
    public RSAKey fromKeyPair(KeyPair keyPair, String kid) {
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(kid != null ? kid : UUID.randomUUID().toString())
                .build();
    }

    /**
     * Extract only the public key portion of an RSAKey.
     * CRITICAL: Only public JWKs must be served from the JWKS endpoint.
     *
     * @param rsaKey Full RSA JWK (with private key)
     * @return RSAKey with ONLY public key material
     */
    public RSAKey toPublicJwk(RSAKey rsaKey) {
        return rsaKey.toPublicJWK();
    }

    /**
     * Parse a JWK from its JSON string representation.
     *
     * @param jwkJson Raw JSON string
     * @return Parsed JWK object
     */
    public JWK parseJwk(String jwkJson) {
        try {
            return JWK.parse(jwkJson);
        } catch (ParseException e) {
            throw new JwkException("Failed to parse JWK from JSON", e);
        }
    }

    /**
     * Parse a JWKS (JWK Set) from its JSON string representation.
     *
     * @param jwksJson Raw JSON string of the JWKS
     * @return Parsed JWKSet
     */
    public JWKSet parseJwkSet(String jwksJson) {
        try {
            return JWKSet.parse(jwksJson);
        } catch (ParseException e) {
            throw new JwkException("Failed to parse JWKS from JSON", e);
        }
    }

    // --- Private helpers ---

    private void validateRsaKeySize(int keySize) {
        if (keySize < 2048) {
            throw new JwkException("RSA key size must be at least 2048 bits per NIST SP 800-131A. Provided: " + keySize);
        }
    }

    private JWSAlgorithm resolveEcAlgorithm(Curve curve) {
        if (Curve.P_256.equals(curve)) return JWSAlgorithm.ES256;
        if (Curve.P_384.equals(curve)) return JWSAlgorithm.ES384;
        if (Curve.P_521.equals(curve)) return JWSAlgorithm.ES512;
        throw new JwkException("Unsupported EC curve: " + curve.getName());
    }
}
