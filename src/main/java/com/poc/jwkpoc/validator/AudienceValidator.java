package com.poc.jwkpoc.validator;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/**
 * Custom JWT Audience Validator — Approach 1 (OAuth2 Resource Server).
 *
 * RFC 7519 Section 4.1.3: The "aud" (audience) claim identifies the recipients
 * that the JWT is intended for. Resource servers MUST validate the audience claim.
 *
 * This validator rejects any JWT that does not contain the expected audience.
 */
@Slf4j
@RequiredArgsConstructor
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error INVALID_AUDIENCE_ERROR = new OAuth2Error(
            "invalid_token",
            "JWT does not contain the required audience",
            "https://tools.ietf.org/html/rfc7519#section-4.1.3"
    );

    private final List<String> requiredAudiences;

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
