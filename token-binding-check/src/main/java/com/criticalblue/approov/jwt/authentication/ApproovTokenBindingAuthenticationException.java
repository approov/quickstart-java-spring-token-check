package com.criticalblue.approov.jwt.authentication;

import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for failures in the validation of the token binding in an Approov token.
 *
 * This exception is only thrown when `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN_BINDING` is set to `true` in the
 * .env file at the root of the project.
 *
 * @see ApproovTokenBindingAuthentication
 */
class ApproovTokenBindingAuthenticationException extends AuthenticationException implements ApproovException {

    private final int httpStatusCode;

    ApproovTokenBindingAuthenticationException(String msg, int httpStatusCode) {
        super(msg);
        this.httpStatusCode = httpStatusCode;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
