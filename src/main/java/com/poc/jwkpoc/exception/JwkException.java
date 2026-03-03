package com.poc.jwkpoc.exception;

/**
 * Domain exception for JWK/JWT operations.
 */
public class JwkException extends RuntimeException {

    public JwkException(String message) {
        super(message);
    }

    public JwkException(String message, Throwable cause) {
        super(message, cause);
    }
}
