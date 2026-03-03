package com.poc.jwkpoc.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Audit trail for key rotation events stored in H2 database.
 * Tracks every key generation/rotation for compliance and debugging.
 */
@Entity
@Table(name = "key_rotation_audit")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
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
}
