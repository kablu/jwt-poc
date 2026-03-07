package com.poc.jwkpoc.entity;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.Objects;

/**
 * Audit trail for key rotation events stored in H2 database.
 * Tracks every key generation/rotation for compliance and debugging.
 */
@Entity
@Table(name = "key_rotation_audit")
public class KeyRotationAudit {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "key_id", nullable = false)
    private String keyId;

    @Column(name = "algorithm", nullable = false)
    private String algorithm;

    @Column(name = "key_size")
    private int keySize;

    @Column(name = "reason")
    private String reason;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "retired_at")
    private Instant retiredAt;

    @Column(name = "is_active", nullable = false)
    private boolean active;

    // --- Constructors ---

    public KeyRotationAudit() {}

    public KeyRotationAudit(Long id, String keyId, String algorithm, int keySize,
                             String reason, Instant createdAt, Instant retiredAt, boolean active) {
        this.id = id;
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.reason = reason;
        this.createdAt = createdAt;
        this.retiredAt = retiredAt;
        this.active = active;
    }

    // --- Builder ---

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private Long id;
        private String keyId;
        private String algorithm;
        private int keySize;
        private String reason;
        private Instant createdAt;
        private Instant retiredAt;
        private boolean active;

        public Builder id(Long id) { this.id = id; return this; }
        public Builder keyId(String keyId) { this.keyId = keyId; return this; }
        public Builder algorithm(String algorithm) { this.algorithm = algorithm; return this; }
        public Builder keySize(int keySize) { this.keySize = keySize; return this; }
        public Builder reason(String reason) { this.reason = reason; return this; }
        public Builder createdAt(Instant createdAt) { this.createdAt = createdAt; return this; }
        public Builder retiredAt(Instant retiredAt) { this.retiredAt = retiredAt; return this; }
        public Builder active(boolean active) { this.active = active; return this; }

        public KeyRotationAudit build() {
            return new KeyRotationAudit(id, keyId, algorithm, keySize, reason, createdAt, retiredAt, active);
        }
    }

    // --- Getters ---

    public Long getId() { return id; }
    public String getKeyId() { return keyId; }
    public String getAlgorithm() { return algorithm; }
    public int getKeySize() { return keySize; }
    public String getReason() { return reason; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getRetiredAt() { return retiredAt; }
    public boolean isActive() { return active; }

    // --- Setters ---

    public void setId(Long id) { this.id = id; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    public void setKeySize(int keySize) { this.keySize = keySize; }
    public void setReason(String reason) { this.reason = reason; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public void setRetiredAt(Instant retiredAt) { this.retiredAt = retiredAt; }
    public void setActive(boolean active) { this.active = active; }

    // --- equals, hashCode, toString ---

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof KeyRotationAudit)) return false;
        KeyRotationAudit that = (KeyRotationAudit) o;
        return keySize == that.keySize && active == that.active
                && Objects.equals(id, that.id) && Objects.equals(keyId, that.keyId)
                && Objects.equals(algorithm, that.algorithm) && Objects.equals(reason, that.reason)
                && Objects.equals(createdAt, that.createdAt) && Objects.equals(retiredAt, that.retiredAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, keyId, algorithm, keySize, reason, createdAt, retiredAt, active);
    }

    @Override
    public String toString() {
        return "KeyRotationAudit{id=" + id + ", keyId='" + keyId + "', algorithm='" + algorithm
                + "', keySize=" + keySize + ", reason='" + reason + "', createdAt=" + createdAt
                + ", retiredAt=" + retiredAt + ", active=" + active + "}";
    }
}
