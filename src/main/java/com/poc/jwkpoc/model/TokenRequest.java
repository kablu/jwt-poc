package com.poc.jwkpoc.model;

import jakarta.validation.constraints.NotBlank;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Request payload for JWT token issuance.
 */
public class TokenRequest {

    @NotBlank(message = "Subject is required")
    private String subject;

    private List<String> audiences;

    private List<String> roles;

    private Map<String, Object> additionalClaims;

    /** Token validity in seconds. Defaults to 3600 (1 hour). */
    private long expirySeconds = 3600L;

    // --- Constructors ---

    public TokenRequest() {}

    public TokenRequest(String subject, List<String> audiences, List<String> roles,
                        Map<String, Object> additionalClaims, long expirySeconds) {
        this.subject = subject;
        this.audiences = audiences;
        this.roles = roles;
        this.additionalClaims = additionalClaims;
        this.expirySeconds = expirySeconds;
    }

    // --- Builder ---

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String subject;
        private List<String> audiences;
        private List<String> roles;
        private Map<String, Object> additionalClaims;
        private long expirySeconds = 3600L;

        public Builder subject(String subject) { this.subject = subject; return this; }
        public Builder audiences(List<String> audiences) { this.audiences = audiences; return this; }
        public Builder roles(List<String> roles) { this.roles = roles; return this; }
        public Builder additionalClaims(Map<String, Object> additionalClaims) { this.additionalClaims = additionalClaims; return this; }
        public Builder expirySeconds(long expirySeconds) { this.expirySeconds = expirySeconds; return this; }

        public TokenRequest build() {
            return new TokenRequest(subject, audiences, roles, additionalClaims, expirySeconds);
        }
    }

    // --- Getters ---

    public String getSubject() { return subject; }
    public List<String> getAudiences() { return audiences; }
    public List<String> getRoles() { return roles; }
    public Map<String, Object> getAdditionalClaims() { return additionalClaims; }
    public long getExpirySeconds() { return expirySeconds; }

    // --- Setters ---

    public void setSubject(String subject) { this.subject = subject; }
    public void setAudiences(List<String> audiences) { this.audiences = audiences; }
    public void setRoles(List<String> roles) { this.roles = roles; }
    public void setAdditionalClaims(Map<String, Object> additionalClaims) { this.additionalClaims = additionalClaims; }
    public void setExpirySeconds(long expirySeconds) { this.expirySeconds = expirySeconds; }

    // --- equals, hashCode, toString ---

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TokenRequest)) return false;
        TokenRequest that = (TokenRequest) o;
        return expirySeconds == that.expirySeconds
                && Objects.equals(subject, that.subject)
                && Objects.equals(audiences, that.audiences)
                && Objects.equals(roles, that.roles)
                && Objects.equals(additionalClaims, that.additionalClaims);
    }

    @Override
    public int hashCode() {
        return Objects.hash(subject, audiences, roles, additionalClaims, expirySeconds);
    }

    @Override
    public String toString() {
        return "TokenRequest{subject='" + subject + "', audiences=" + audiences
                + ", roles=" + roles + ", expirySeconds=" + expirySeconds + "}";
    }
}
