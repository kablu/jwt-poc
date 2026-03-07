package com.poc.jwkpoc.service;

import com.poc.jwkpoc.entity.AudienceRegistry;
import com.poc.jwkpoc.model.AudienceRegistryRequest;
import com.poc.jwkpoc.model.AudienceRegistryResponse;
import com.poc.jwkpoc.repository.AudienceRegistryRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Audience Registry Service.
 *
 * Kaam:
 *  1. Naye applications ko register karna (POST /api/audiences/register)
 *  2. Registered audiences ki list dena (GET /api/audiences)
 *  3. Token issue karne se pehle validate karna ki audience registered hai ya nahi
 */
@Service
public class AudienceRegistryService {

    private static final Logger log = LoggerFactory.getLogger(AudienceRegistryService.class);

    private final AudienceRegistryRepository repository;

    @Autowired
    public AudienceRegistryService(AudienceRegistryRepository repository) {
        this.repository = repository;
    }

    /**
     * Naya application register karo as audience.
     *
     * @param request  { audienceName, description, contactEmail }
     * @return         Registered audience ki details
     * @throws IllegalArgumentException  agar naam already registered hai
     */
    public AudienceRegistryResponse register(AudienceRegistryRequest request) {
        if (repository.existsByAudienceName(request.getAudienceName())) {
            throw new IllegalArgumentException(
                "Audience already registered: " + request.getAudienceName()
            );
        }

        AudienceRegistry entity = AudienceRegistry.builder()
                .audienceName(request.getAudienceName())
                .description(request.getDescription())
                .contactEmail(request.getContactEmail())
                .active(true)
                .build();

        AudienceRegistry saved = repository.save(entity);
        log.info("New audience registered: name={}, id={}", saved.getAudienceName(), saved.getId());
        return toResponse(saved);
    }

    /**
     * Sabhi active audiences ki list.
     * GET /api/audiences
     */
    public List<AudienceRegistryResponse> getAllActive() {
        return repository.findAllByActiveTrue()
                .stream()
                .map(this::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * Check karo ki audience registered aur active hai ya nahi.
     * TokenController yeh method call karta hai before issuing token.
     *
     * @param audienceName  e.g. "jwk-poc-api"
     * @return true if registered and active
     */
    public boolean isValidAudience(String audienceName) {
        return repository.findByAudienceName(audienceName)
                .map(AudienceRegistry::isActive)
                .orElse(false);
    }

    // ─── Private helper ───────────────────────────────────────────────────

    private AudienceRegistryResponse toResponse(AudienceRegistry entity) {
        return AudienceRegistryResponse.builder()
                .id(entity.getId())
                .audienceName(entity.getAudienceName())
                .description(entity.getDescription())
                .active(entity.isActive())
                .contactEmail(entity.getContactEmail())
                .registeredAt(entity.getRegisteredAt())
                .updatedAt(entity.getUpdatedAt())
                .build();
    }
}
