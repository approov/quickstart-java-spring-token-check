package com.criticalblue.approov.jwt.authentication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;

import org.springframework.security.core.Authentication;

/**
 * The Interface to be used in the Approov authentication.
 *
 * @see ApproovAuthentication
 */
public interface ApproovJwtAuthentication extends Authentication {

    boolean isValidApproovHeaderClaim();

    Claims getApproovTokenPayloadClaims();

    void checkWith(byte[] secret) throws JwtException;
}
