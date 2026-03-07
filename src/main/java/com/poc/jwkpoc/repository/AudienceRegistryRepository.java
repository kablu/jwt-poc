package com.poc.jwkpoc.repository;

import com.poc.jwkpoc.entity.AudienceRegistry;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * AudienceRegistry Repository.
 *
 * H2 (in-memory) database mein audience_registry table ke saath kaam karta hai.
 */
@Repository
public interface AudienceRegistryRepository extends JpaRepository<AudienceRegistry, Long> {

    /** Name se audience dhundhna */
    Optional<AudienceRegistry> findByAudienceName(String audienceName);

    /** Sirf active audiences ki list */
    List<AudienceRegistry> findAllByActiveTrue();

    /** Check — kya yeh naam already registered hai? */
    boolean existsByAudienceName(String audienceName);
}
