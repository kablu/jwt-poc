package com.poc.jwkpoc.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request body for POST /api/audiences/register
 *
 * Example JSON:
 * {
 *   "audienceName" : "jwk-poc-api",
 *   "description"  : "JWK POC Resource Server running on port 8084",
 *   "contactEmail" : "team@poc.local"
 * }
 */
public class AudienceRegistryRequest {

    @NotBlank(message = "audienceName is required")
    @Pattern(regexp = "^[a-z0-9-]+$",
             message = "audienceName: only lowercase letters, digits, hyphens allowed")
    private String audienceName;

    @NotBlank(message = "description is required")
    private String description;

    private String contactEmail;

    // ─── Constructors ─────────────────────────────────────────────────────

    public AudienceRegistryRequest() {}

    public AudienceRegistryRequest(String audienceName, String description, String contactEmail) {
        this.audienceName = audienceName;
        this.description  = description;
        this.contactEmail = contactEmail;
    }

    // ─── Getters / Setters ────────────────────────────────────────────────

    public String getAudienceName()  { return audienceName; }
    public String getDescription()   { return description; }
    public String getContactEmail()  { return contactEmail; }

    public void setAudienceName(String audienceName) { this.audienceName = audienceName; }
    public void setDescription(String description)   { this.description  = description; }
    public void setContactEmail(String email)        { this.contactEmail = email; }

    @Override
    public String toString() {
        return "AudienceRegistryRequest{audienceName='" + audienceName + "'}";
    }
}
