package com.poc.jwkpoc.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Audience Registry Entity.
 *
 * Har woh application jisko jwt-poc se token chahiye,
 * woh pehle yahan register hogi.
 *
 * Example:
 *   audienceName = "jwk-poc-api"  ← Resource Server ka naam
 *   description  = "JWK POC Resource Server"
 *   active       = true
 */
@Entity
@Table(name = "audience_registry")
public class AudienceRegistry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Application ka unique naam — yahi JWT "aud" claim mein jayega */
    @Column(name = "audience_name", unique = true, nullable = false)
    private String audienceName;

    @Column(nullable = false)
    private String description;

    /** false karne par is audience ke liye token issue nahi hoga */
    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    @Column(name = "contact_email")
    private String contactEmail;

    @Column(name = "registered_at", updatable = false)
    private LocalDateTime registeredAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        registeredAt = LocalDateTime.now();
        updatedAt    = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // ─── Builder ──────────────────────────────────────────────────────────

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private String audienceName;
        private String description;
        private boolean active = true;
        private String contactEmail;

        public Builder audienceName(String v)  { this.audienceName = v; return this; }
        public Builder description(String v)   { this.description  = v; return this; }
        public Builder active(boolean v)       { this.active       = v; return this; }
        public Builder contactEmail(String v)  { this.contactEmail = v; return this; }

        public AudienceRegistry build() {
            AudienceRegistry e = new AudienceRegistry();
            e.audienceName = this.audienceName;
            e.description  = this.description;
            e.active       = this.active;
            e.contactEmail = this.contactEmail;
            return e;
        }
    }

    // ─── Getters ──────────────────────────────────────────────────────────

    public Long           getId()            { return id; }
    public String         getAudienceName()  { return audienceName; }
    public String         getDescription()   { return description; }
    public boolean        isActive()         { return active; }
    public String         getContactEmail()  { return contactEmail; }
    public LocalDateTime  getRegisteredAt()  { return registeredAt; }
    public LocalDateTime  getUpdatedAt()     { return updatedAt; }

    // ─── Setters ──────────────────────────────────────────────────────────

    public void setId(Long id)                        { this.id            = id; }
    public void setAudienceName(String audienceName)  { this.audienceName  = audienceName; }
    public void setDescription(String description)    { this.description   = description; }
    public void setActive(boolean active)             { this.active        = active; }
    public void setContactEmail(String email)         { this.contactEmail  = email; }
    public void setRegisteredAt(LocalDateTime t)      { this.registeredAt  = t; }
    public void setUpdatedAt(LocalDateTime t)         { this.updatedAt     = t; }

    // ─── equals / hashCode / toString ─────────────────────────────────────

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AudienceRegistry)) return false;
        AudienceRegistry that = (AudienceRegistry) o;
        return Objects.equals(audienceName, that.audienceName);
    }

    @Override
    public int hashCode() { return Objects.hash(audienceName); }

    @Override
    public String toString() {
        return "AudienceRegistry{id=" + id + ", audienceName='" + audienceName
                + "', active=" + active + "}";
    }
}
