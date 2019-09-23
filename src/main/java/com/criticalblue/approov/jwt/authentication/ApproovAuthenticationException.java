package com.criticalblue.approov.jwt.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Custom exception for failures when verifying the Approov token signature and expiration time.
 *
 * This exception is only thrown when `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` is set to `true` in the .env file at the
 * root of the project.
 *
 * @see ApproovAuthentication
 */
class ApproovAuthenticationException extends AuthenticationException implements ApproovException {

    private final static Logger logger = LoggerFactory.getLogger(ApproovAuthenticationException.class);

    private final int httpStatusCode;

    public ApproovAuthenticationException(String msg, int httpStatusCode) {

        super(msg);

        this.httpStatusCode = httpStatusCode;

        logger.error( msg + " -> See: " + getStackTrace()[0].toString());
    }

    public int getHttpStatusCode() {
        return this.httpStatusCode;
    }
}
