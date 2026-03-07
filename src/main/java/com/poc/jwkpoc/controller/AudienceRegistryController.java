package com.poc.jwkpoc.controller;

import com.poc.jwkpoc.model.AudienceRegistryRequest;
import com.poc.jwkpoc.model.AudienceRegistryResponse;
import com.poc.jwkpoc.service.AudienceRegistryService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Audience Registry Controller.
 *
 * Endpoints (sabhi public — no JWT required):
 *
 *   POST /api/audiences/register          — Naya application register karo
 *   GET  /api/audiences                   — Sabhi registered audiences dekho
 *   GET  /api/audiences/validate/{name}   — Check karo ki registered hai ya nahi
 *
 * Usage (Postman se):
 *   POST http://localhost:8083/api/audiences/register
 *   Body: { "audienceName": "jwk-poc-api", "description": "Resource Server", "contactEmail": "admin@poc.local" }
 */
@RestController
@RequestMapping("/api/audiences")
public class AudienceRegistryController {

    private static final Logger log = LoggerFactory.getLogger(AudienceRegistryController.class);

    private final AudienceRegistryService service;

    @Autowired
    public AudienceRegistryController(AudienceRegistryService service) {
        this.service = service;
    }

    /**
     * Naya application register karo.
     * POST /api/audiences/register
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody AudienceRegistryRequest request) {
        log.info("Audience registration request: name={}", request.getAudienceName());
        try {
            AudienceRegistryResponse response = service.register(request);
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of(
                        "error",   "ALREADY_REGISTERED",
                        "message", e.getMessage()
                    ));
        }
    }

    /**
     * Sabhi active audiences ki list.
     * GET /api/audiences
     */
    @GetMapping
    public ResponseEntity<List<AudienceRegistryResponse>> getAllAudiences() {
        return ResponseEntity.ok(service.getAllActive());
    }

    /**
     * Check karo — kya yeh audience registered hai?
     * GET /api/audiences/validate/jwk-poc-api
     */
    @GetMapping("/validate/{audienceName}")
    public ResponseEntity<Map<String, Object>> validateAudience(
            @PathVariable String audienceName) {
        boolean valid = service.isValidAudience(audienceName);
        return ResponseEntity.ok(Map.of(
            "audienceName", audienceName,
            "registered",   valid,
            "message",      valid
                                ? "'" + audienceName + "' registered aur active hai ✅"
                                : "'" + audienceName + "' registered nahi hai ❌"
        ));
    }
}
