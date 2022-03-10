package com.criticalblue.approov.jwt.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.jsonwebtoken.Claims;

import org.apache.tomcat.util.codec.binary.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationServiceException;

public class ApproovTokenBindingAuthentication {

    private static Logger logger = LoggerFactory.getLogger(ApproovAuthentication.class);

    /**
     * Checks the value in the key `pay` of an Approov token matches the token binding header, that by default is
     * the value for the `Authorization` header.
     *
     * @param tokenBindingHeader        Extracted from an header, that by default is the Authorization header.
     * @param approovTokenPayloadClaims Extracted from the already verified Approov token.
     * @param approovConfig             Extracted from the .env file in the root of the package.
     * @return
     */
    boolean checkClaimMatchesFor(String tokenBindingHeader, Claims approovTokenPayloadClaims,  ApproovConfig approovConfig) {

        if (tokenBindingHeader == null && approovConfig.isToAbortRequestOnInvalidTokenBinding()) {
            throw new ApproovTokenBindingAuthenticationException("The token binding header value is null.", HttpStatus.BAD_REQUEST.value());
        }

        final String approovTokenBindingClaim = getApproovTokenBindingClaim(approovTokenPayloadClaims, approovConfig);

        if (approovTokenBindingClaim == null) {

            logger.info("Request approved, but not able to check the token binding in the Approov token.");

            // When is `null`, it means we have not met yet a condition to fail the check when the claim is missing.
            // @see getApproovTokenBindingClaim() for the conditions that will throw an exception.
            return true;
        }

        boolean isValidTokenBinding = getHashBase64Encoded(tokenBindingHeader).equals(approovTokenBindingClaim);

        if (isValidTokenBinding) {
            logger.info("Request approved with a valid token binding in the Approov token.");
            return isValidTokenBinding;
        }

        // When the token binding header does not match the value in key `pay` of the Approov token, the request is
        // aborted, but only if it is enabled in the Approov configuration.
        if (approovConfig.isToAbortRequestOnInvalidTokenBinding()) {
            throw new ApproovTokenBindingAuthenticationException("The token binding header does not match the key `pay` in the Approov token.", HttpStatus.UNAUTHORIZED.value());
        }

        logger.info("Request not approved, because the token binding header does not match the key `pay` in the Approov token.");

        return false;
    }

    private String getApproovTokenBindingClaim(Claims approovTokenPayloadClaims, ApproovConfig approovConfig) {

        if (approovTokenPayloadClaims == null) {

            if (approovConfig.isToAbortRequestOnInvalidTokenBinding()) {
                throw new ApproovTokenBindingAuthenticationException("Approov token payload is null.", HttpStatus.INTERNAL_SERVER_ERROR.value());
            }

            logger.warn("Approov token payload is null.");

            return null;
        }

        if ( ! approovTokenPayloadClaims.containsKey("pay") ) {

            if (approovConfig.isToAbortRequestOnInvalidTokenBinding()) {
                throw new ApproovTokenBindingAuthenticationException("The key `pay`, for the token binding, is missing in the Approov token payload.", HttpStatus.BAD_REQUEST.value());
            }

            logger.warn("The key `pay`, for the token binding, is missing in the Approov token payload.");

            // The Approov the token binding is optional, so we cannot throw an exception...
            return null;
        }

        final String approovTokenBindingClaim = approovTokenPayloadClaims.get("pay").toString();

        if (approovTokenBindingClaim == null || approovTokenBindingClaim.trim().equals("")) {

            if (approovConfig.isToAbortRequestOnInvalidTokenBinding()) {
                throw new ApproovTokenBindingAuthenticationException("The token binding in the Approov token is null or empty.", HttpStatus.BAD_REQUEST.value());
            }

            logger.warn("The token binding in the Approov token is null or empty.");

            return null;
        }

        return approovTokenBindingClaim;
    }

    private String getHashBase64Encoded(String value) {

        final MessageDigest digest;

        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationServiceException(e.getMessage());
        }

        byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
        return  Base64.encodeBase64String(hash);
    }
}
