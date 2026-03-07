package com.poc.jwkpoc.validator;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Custom JWT Audience Validator — Approach 1 (OAuth2 Resource Server).
 *
 * RFC 7519 Section 4.1.3: The "aud" (audience) claim identifies the recipients
 * that the JWT is intended for. Resource servers MUST validate the audience claim.
 *
 * This validator rejects any JWT that does not contain the expected audience.
 */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_AUDIENCE_ERROR = new OAuth2Error(
            "invalid_token",
            "JWT does not contain the required audience",
            "https://tools.ietf.org/html/rfc7519#section-4.1.3"
    );

    private static final Logger log = LoggerFactory.getLogger(AudienceValidator.class);

    private final List<String> requiredAudiences;

    public AudienceValidator(List<String> requiredAudiences) {
        this.requiredAudiences = requiredAudiences;
    }

    /**
     * Validate that the JWT audience claim contains at least one required audience.
     *
     * @param jwt The decoded JWT
     * @return Success if audience matches; failure otherwise
     */
    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> tokenAudiences = jwt.getAudience();

        if (tokenAudiences == null || tokenAudiences.isEmpty()) {
            log.warn("JWT missing audience claim for subject={}", jwt.getSubject());
            return OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE_ERROR);
        }

        boolean hasRequiredAudience = requiredAudiences.stream()
                .anyMatch(tokenAudiences::contains);

        if (!hasRequiredAudience) {
            log.warn("JWT audience mismatch. token-aud={}, required={}",
                    tokenAudiences, requiredAudiences);
            return OAuth2TokenValidatorResult.failure(INVALID_AUDIENCE_ERROR);
        }

        log.debug("JWT audience validated successfully for subject={}", jwt.getSubject());
        return OAuth2TokenValidatorResult.success();
    }
}
