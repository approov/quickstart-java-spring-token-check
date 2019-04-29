package com.criticalblue.approov.jwt.authentication;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for failures in the validation of a custom payload claim in an Approov token.
 *
 * This exception is only thrown when `APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM` is set to `true` in the
 * .env file at the root of the project.
 *
 * @see ApproovPayloadAuthentication
 */
class ApproovPayloadAuthenticationException extends AuthenticationException {

    private final static Logger logger = LoggerFactory.getLogger(ApproovPayloadAuthenticationException.class);

    ApproovPayloadAuthenticationException(String msg) {

        super(msg);

        logger.error( msg + " -> See: " + getStackTrace()[0].toString());
    }
}
