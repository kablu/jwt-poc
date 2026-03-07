package com.poc.jwkpoc.model;

import java.time.LocalDateTime;

/**
 * Response for audience registration and listing APIs.
 */
public class AudienceRegistryResponse {

    private Long          id;
    private String        audienceName;
    private String        description;
    private boolean       active;
    private String        contactEmail;
    private LocalDateTime registeredAt;
    private LocalDateTime updatedAt;

    // ─── Builder ──────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private Long          id;
        private String        audienceName;
        private String        description;
        private boolean       active;
        private String        contactEmail;
        private LocalDateTime registeredAt;
        private LocalDateTime updatedAt;

        public Builder id(Long v)                   { this.id           = v; return this; }
        public Builder audienceName(String v)        { this.audienceName = v; return this; }
        public Builder description(String v)         { this.description  = v; return this; }
        public Builder active(boolean v)             { this.active       = v; return this; }
        public Builder contactEmail(String v)        { this.contactEmail = v; return this; }
        public Builder registeredAt(LocalDateTime v) { this.registeredAt = v; return this; }
        public Builder updatedAt(LocalDateTime v)    { this.updatedAt    = v; return this; }

        public AudienceRegistryResponse build() {
            AudienceRegistryResponse r = new AudienceRegistryResponse();
            r.id           = this.id;
            r.audienceName = this.audienceName;
            r.description  = this.description;
            r.active       = this.active;
            r.contactEmail = this.contactEmail;
            r.registeredAt = this.registeredAt;
            r.updatedAt    = this.updatedAt;
            return r;
        }
    }

    // ─── Getters / Setters ────────────────────────────────────────────────

    public Long          getId()            { return id; }
    public String        getAudienceName()  { return audienceName; }
    public String        getDescription()   { return description; }
    public boolean       isActive()         { return active; }
    public String        getContactEmail()  { return contactEmail; }
    public LocalDateTime getRegisteredAt()  { return registeredAt; }
    public LocalDateTime getUpdatedAt()     { return updatedAt; }

    public void setId(Long id)                        { this.id           = id; }
    public void setAudienceName(String audienceName)  { this.audienceName = audienceName; }
    public void setDescription(String description)    { this.description  = description; }
    public void setActive(boolean active)             { this.active       = active; }
    public void setContactEmail(String email)         { this.contactEmail = email; }
    public void setRegisteredAt(LocalDateTime t)      { this.registeredAt = t; }
    public void setUpdatedAt(LocalDateTime t)         { this.updatedAt    = t; }
}
