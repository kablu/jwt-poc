package com.poc.jwkpoc.model;

import java.util.Objects;

/**
 * Response payload containing the issued JWT access token.
 */
public class TokenResponse {

    private String accessToken;
    private String tokenType;
    private long expiresIn;
    private String keyId;
    private String algorithm;

    // --- Constructors ---

    public TokenResponse() {}

    public TokenResponse(String accessToken, String tokenType, long expiresIn,
                         String keyId, String algorithm) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.expiresIn = expiresIn;
        this.keyId = keyId;
        this.algorithm = algorithm;
    }

    // --- Builder ---

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String accessToken;
        private String tokenType;
        private long expiresIn;
        private String keyId;
        private String algorithm;

        public Builder accessToken(String accessToken) { this.accessToken = accessToken; return this; }
        public Builder tokenType(String tokenType) { this.tokenType = tokenType; return this; }
        public Builder expiresIn(long expiresIn) { this.expiresIn = expiresIn; return this; }
        public Builder keyId(String keyId) { this.keyId = keyId; return this; }
        public Builder algorithm(String algorithm) { this.algorithm = algorithm; return this; }

        public TokenResponse build() {
            return new TokenResponse(accessToken, tokenType, expiresIn, keyId, algorithm);
        }
    }

    // --- Getters ---

    public String getAccessToken() { return accessToken; }
    public String getTokenType() { return tokenType; }
    public long getExpiresIn() { return expiresIn; }
    public String getKeyId() { return keyId; }
    public String getAlgorithm() { return algorithm; }

    // --- Setters ---

    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }
    public void setExpiresIn(long expiresIn) { this.expiresIn = expiresIn; }
    public void setKeyId(String keyId) { this.keyId = keyId; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }

    // --- equals, hashCode, toString ---

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TokenResponse)) return false;
        TokenResponse that = (TokenResponse) o;
        return expiresIn == that.expiresIn
                && Objects.equals(accessToken, that.accessToken)
                && Objects.equals(tokenType, that.tokenType)
                && Objects.equals(keyId, that.keyId)
                && Objects.equals(algorithm, that.algorithm);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken, tokenType, expiresIn, keyId, algorithm);
    }

    @Override
    public String toString() {
        return "TokenResponse{tokenType='" + tokenType + "', expiresIn=" + expiresIn
                + ", keyId='" + keyId + "', algorithm='" + algorithm + "'}";
    }
}
