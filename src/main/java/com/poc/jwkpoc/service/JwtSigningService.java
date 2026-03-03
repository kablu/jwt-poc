package com.poc.jwkpoc.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.*;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.poc.jwkpoc.exception.JwkException;
import com.poc.jwkpoc.model.TokenRequest;
import com.poc.jwkpoc.model.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * JWT Signing and Verification Service.
 *
 * Implements Approach 2 (Nimbus JOSE + JWT manual control) for:
 *  - Issuing signed JWTs using the active RSA private key
 *  - Verifying JWTs using the published JWKS (Approach 1 pattern)
 *
 * Security properties:
 *  - Algorithm: RS256 (RSASSA-PKCS1-v1_5 + SHA-256)
 *  - Key size: 2048 bits minimum (enforced by JwkService)
 *  - kid header is always set for JWKS key matching and rotation support
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JwtSigningService {

    private final JwkRotationService rotationService;

    @Value("${jwk.issuer:https://poc.jwk-poc.local}")
    private String issuer;

    /**
     * Issue a signed JWT for the given subject and claims.
     *
     * JWT Header: { "alg": "RS256", "kid": "<active-kid>", "typ": "JWT" }
     * JWT Claims: sub, iss, iat, exp, aud, roles (+ any additionalClaims)
     *
     * @param request TokenRequest containing subject, audiences, roles, expiry
     * @return TokenResponse with serialised JWT and metadata
     */
    public TokenResponse issueToken(TokenRequest request) {
        RSAKey signingKey = rotationService.getCurrentSigningKey();

        try {
            JWSSigner signer = new RSASSASigner(signingKey);

            Instant now = Instant.now();
            Instant expiry = now.plusSeconds(request.getExpirySeconds());

            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .subject(request.getSubject())
                    .issuer(issuer)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiry));

            if (request.getAudiences() != null && !request.getAudiences().isEmpty()) {
                claimsBuilder.audience(request.getAudiences());
            }

            if (request.getRoles() != null && !request.getRoles().isEmpty()) {
                claimsBuilder.claim("roles", request.getRoles());
            }

            if (request.getAdditionalClaims() != null) {
                request.getAdditionalClaims().forEach(claimsBuilder::claim);
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(signingKey.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claimsBuilder.build());
            signedJWT.sign(signer);

            String serialisedToken = signedJWT.serialize();

            log.debug("Issued JWT for subject={} with kid={}, expires={}",
                    request.getSubject(), signingKey.getKeyID(), expiry);

            return TokenResponse.builder()
                    .accessToken(serialisedToken)
                    .tokenType("Bearer")
                    .expiresIn(request.getExpirySeconds())
                    .keyId(signingKey.getKeyID())
                    .algorithm(JWSAlgorithm.RS256.getName())
                    .build();

        } catch (JOSEException e) {
            throw new JwkException("Failed to sign JWT for subject=" + request.getSubject(), e);
        }
    }

    /**
     * Verify a JWT using the current public JWKS.
     * Validates: signature, expiry, and issuer.
     *
     * @param token Serialised JWT string
     * @return Parsed and validated JWTClaimsSet
     */
    public JWTClaimsSet verifyToken(String token) {
        JWKSet publicJwkSet = rotationService.getPublicJwkSet();

        try {
            ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

            JWSKeySelector<SimpleSecurityContext> keySelector =
                    new JWSVerificationKeySelector<>(
                            JWSAlgorithm.RS256,
                            new ImmutableJWKSet<>(publicJwkSet)
                    );

            jwtProcessor.setJWSKeySelector(keySelector);

            JWTClaimsSet claimsSet = jwtProcessor.process(token, null);

            log.debug("JWT verified successfully for subject={}", claimsSet.getSubject());
            return claimsSet;

        } catch (ParseException | JOSEException | BadJOSEException e) {
            throw new JwkException("JWT verification failed: " + e.getMessage(), e);
        }
    }

    /**
     * Quick signature-only verification using a specific RSAKey.
     * Useful for unit testing without full JWTProcessor setup.
     *
     * @param token  Serialised JWT
     * @param rsaKey Public RSA key to verify with
     * @return true if signature is valid
     */
    public boolean verifySignatureOnly(String token, RSAKey rsaKey) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            return signedJWT.verify(verifier);
        } catch (ParseException | JOSEException e) {
            log.warn("Signature verification failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Parse a JWT without verification — for inspection only.
     * WARNING: Do NOT use for authentication decisions.
     *
     * @param token Serialised JWT
     * @return Claims from the JWT payload (UNVERIFIED)
     */
    public Map<String, Object> parseUnverified(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            return signedJWT.getJWTClaimsSet().toJSONObject();
        } catch (ParseException e) {
            throw new JwkException("Failed to parse JWT: " + e.getMessage(), e);
        }
    }
}
