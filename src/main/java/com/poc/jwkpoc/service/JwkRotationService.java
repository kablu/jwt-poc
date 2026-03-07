package com.poc.jwkpoc.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.poc.jwkpoc.entity.KeyRotationAudit;
import com.poc.jwkpoc.exception.JwkException;
import com.poc.jwkpoc.repository.KeyRotationAuditRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * PKI Key Rotation Service — RFC 7517 compliant key lifecycle management.
 *
 * Key Rotation Strategy (from jwk-plan.md):
 *   Phase 1: Generate new key, publish alongside old key in JWKS
 *   Phase 2: Sign new JWTs with new key (kid in JWT header updated)
 *   Phase 3: Allow old JWTs to expire naturally (overlap window)
 *   Phase 4: Remove old key from JWKS
 *
 * Audit trail is persisted to H2 database via KeyRotationAuditRepository.
 */
@Service
public class JwkRotationService {

    private static final Logger log = LoggerFactory.getLogger(JwkRotationService.class);
    private static final int RSA_KEY_SIZE = 2048;
    private static final int MAX_ACTIVE_KEYS = 2; // Current + one previous (overlap period)

    private final JwkService jwkService;
    private final KeyRotationAuditRepository auditRepository;

    @Autowired
    public JwkRotationService(JwkService jwkService, KeyRotationAuditRepository auditRepository) {
        this.jwkService = jwkService;
        this.auditRepository = auditRepository;
    }

    /**
     * Thread-safe store: kid → RSAKey (full, including private key).
     * Private keys NEVER leave this service.
     */
    private final Map<String, RSAKey> keyStore = new ConcurrentHashMap<>();

    /**
     * Atomic reference to the currently published JWKS (PUBLIC keys only).
     */
    private final AtomicReference<JWKSet> publicJwkSet = new AtomicReference<>();

    /**
     * kid of the key currently used for signing new JWTs.
     */
    private final AtomicReference<String> activeKid = new AtomicReference<>();

    /**
     * Initialise on startup — generate the first signing key.
     */
    @PostConstruct
    public void init() {
        log.info("Initialising JWK key store...");
        rotateKey("startup-init");
    }

    /**
     * Scheduled key rotation — runs on the 1st of every month at midnight.
     * Override with spring.task.scheduling.pool.size if needed.
     */
    @Scheduled(cron = "${jwk.rotation.cron:0 0 0 1 * *}")
    public void scheduledRotation() {
        log.info("Scheduled key rotation triggered");
        rotateKey("scheduled-monthly-rotation");
    }

    /**
     * Generate a new RSA key, publish it alongside the current key (overlap),
     * update the active signing kid, and retire the oldest key if we exceed MAX_ACTIVE_KEYS.
     *
     * @param reason Human-readable reason for rotation (for audit trail)
     */
    public synchronized void rotateKey(String reason) {
        String newKid = "key-" + Instant.now().toEpochMilli();
        RSAKey newKey = jwkService.generateRsaJwk(RSA_KEY_SIZE, newKid);

        // Store full key (private + public) internally
        keyStore.put(newKid, newKey);
        activeKid.set(newKid);

        // Retire oldest key if we have more than MAX_ACTIVE_KEYS
        if (keyStore.size() > MAX_ACTIVE_KEYS) {
            String oldestKid = keyStore.keySet().stream()
                    .filter(kid -> !kid.equals(newKid))
                    .min(String::compareTo)
                    .orElse(null);

            if (oldestKid != null) {
                keyStore.remove(oldestKid);
                auditRepository.retireKey(oldestKid, Instant.now());
                log.info("Retired key kid={}", oldestKid);
            }
        }

        // Rebuild published JWKS — public keys only (RFC 7517: never expose private key material)
        List<com.nimbusds.jose.jwk.JWK> publicKeys = new ArrayList<>();
        keyStore.values().forEach(k -> publicKeys.add(k.toPublicJWK()));
        publicJwkSet.set(new JWKSet(publicKeys));

        // Persist audit record to H2
        auditRepository.save(KeyRotationAudit.builder()
                .keyId(newKid)
                .algorithm(JWSAlgorithm.RS256.getName())
                .keySize(RSA_KEY_SIZE)
                .reason(reason)
                .createdAt(Instant.now())
                .active(true)
                .build());

        log.info("Key rotation complete. Active kid={}, total active keys={}, reason={}",
                newKid, keyStore.size(), reason);
    }

    /**
     * Retrieve the current signing key (private key included) for JWT signing.
     * ONLY used internally by JwtSigningService.
     *
     * @return The active RSAKey with private key material
     */
    public RSAKey getCurrentSigningKey() {
        String kid = activeKid.get();
        RSAKey key = keyStore.get(kid);
        if (key == null) {
            throw new JwkException("No active signing key available. kid=" + kid);
        }
        return key;
    }

    /**
     * Retrieve the currently published JWKS (public keys only).
     * This is what gets served from /.well-known/jwks.json.
     *
     * @return JWKSet containing only public key material
     */
    public JWKSet getPublicJwkSet() {
        JWKSet jwkSet = publicJwkSet.get();
        if (jwkSet == null) {
            throw new JwkException("JWKS not initialised yet");
        }
        return jwkSet;
    }

    /**
     * Return the kid of the currently active signing key.
     */
    public String getActiveKid() {
        return activeKid.get();
    }

    /**
     * Return how many keys are currently in the key store (active overlap window).
     */
    public int getActiveKeyCount() {
        return keyStore.size();
    }
}
