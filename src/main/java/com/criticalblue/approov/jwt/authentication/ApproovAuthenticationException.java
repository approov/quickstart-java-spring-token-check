package com.criticalblue.approov.jwt.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for failures when verifying the Approov token signature and expiration time.
 *
 * This exception is only thrown when `APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN` is set to `true` in the .env file at the
 * root of the project.
 *
 * @see ApproovAuthentication
 */
class ApproovAuthenticationException extends AuthenticationException {

    private final static Logger logger = LoggerFactory.getLogger(ApproovAuthenticationException.class);

    ApproovAuthenticationException(String msg) {

        super(msg);

        logger.error( msg + " -> See: " + getStackTrace()[0].toString());
    }
}
