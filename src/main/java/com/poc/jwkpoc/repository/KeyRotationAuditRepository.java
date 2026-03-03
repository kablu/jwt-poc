package com.poc.jwkpoc.repository;

import com.poc.jwkpoc.entity.KeyRotationAudit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository for key rotation audit records.
 */
@Repository
public interface KeyRotationAuditRepository extends JpaRepository<KeyRotationAudit, Long> {

    List<KeyRotationAudit> findByActiveTrue();

    Optional<KeyRotationAudit> findByKeyId(String keyId);

    @Modifying
    @Transactional
    @Query("UPDATE KeyRotationAudit k SET k.active = false, k.retiredAt = :retiredAt WHERE k.keyId = :keyId")
    void retireKey(String keyId, Instant retiredAt);

    List<KeyRotationAudit> findAllByOrderByCreatedAtDesc();
}
