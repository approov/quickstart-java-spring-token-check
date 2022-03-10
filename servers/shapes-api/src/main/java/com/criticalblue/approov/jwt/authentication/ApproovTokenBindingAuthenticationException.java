package com.criticalblue.approov.jwt.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private final static Logger logger = LoggerFactory.getLogger(ApproovTokenBindingAuthenticationException.class);
    private final int httpStatusCode;

    ApproovTokenBindingAuthenticationException(String msg, int httpStatusCode) {

        super(msg);

        this.httpStatusCode = httpStatusCode;

        logger.error( msg + " -> See: " + getStackTrace()[0].toString());
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
