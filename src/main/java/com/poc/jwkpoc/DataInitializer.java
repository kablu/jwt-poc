package com.poc.jwkpoc;

import com.poc.jwkpoc.model.AudienceRegistryRequest;
import com.poc.jwkpoc.service.AudienceRegistryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/**
 * DataInitializer — Application start hone par default audiences pre-register karta hai.
 *
 * Jab bhi naya application (resource server) banein:
 *   1. Yahan uski entry add karo — YA —
 *   2. POST /api/audiences/register API call karo (runtime mein)
 */
@Component
public class DataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final AudienceRegistryService audienceRegistryService;

    @Autowired
    public DataInitializer(AudienceRegistryService audienceRegistryService) {
        this.audienceRegistryService = audienceRegistryService;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void initDefaultAudiences() {
        log.info("=== Initializing default audiences ===");

        // ── Default audience 1: jwk-poc-api (Resource Server) ──────────────
        registerIfAbsent(
            "jwk-poc-api",
            "JWK POC Resource Server — port 8084 pe chalta hai",
            "team@poc.local"
        );

        // ── Nayi application aane par yahan add karo ────────────────────────
        // registerIfAbsent("mobile-backend-api", "Mobile App Backend — port 8085", "mobile@poc.local");
        // registerIfAbsent("admin-dashboard",    "Admin Dashboard — port 8086",    "admin@poc.local");

        log.info("=== Audience initialization complete ===");
    }

    // ─── Private helper ───────────────────────────────────────────────────

    private void registerIfAbsent(String name, String description, String email) {
        try {
            AudienceRegistryRequest req = new AudienceRegistryRequest(name, description, email);
            audienceRegistryService.register(req);
            log.info("  [+] Registered: '{}'", name);
        } catch (IllegalArgumentException e) {
            // Already registered (server restart) — this is fine
            log.info("  [=] Already registered: '{}'  (skipping)", name);
        }
    }
}
