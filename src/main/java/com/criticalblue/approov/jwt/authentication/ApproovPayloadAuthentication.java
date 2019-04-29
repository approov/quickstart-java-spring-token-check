package com.criticalblue.approov.jwt.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import io.jsonwebtoken.Claims;

import org.apache.tomcat.util.codec.binary.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationServiceException;

public class ApproovPayloadAuthentication {

    private static Logger logger = LoggerFactory.getLogger(ApproovAuthentication.class);

    /**
     * Checks the value in the key `pay` of an Approov token payload matches the request claim value, that by default is
     * the value for the `Authorization` header.
     *
     * @param approovHeaderClaim        Extracted from an header, that by default is the Authorization header.
     * @param approovTokenPayloadClaims Extracted from the already verified Approov token.
     * @param approovConfig             Extracted from the .env file in the root of the package.
     * @return
     */
    boolean checkClaimMatchesFor(String approovHeaderClaim, Claims approovTokenPayloadClaims,  ApproovConfig approovConfig) {

        if (approovHeaderClaim == null && approovConfig.isToAbortRequestOnInvalidCustomPayloadClaim()) {
            throw new ApproovPayloadAuthenticationException("The Approov header claim value is null.");
        }

        final String approovCustomPayloadClaim = getApproovCustomPayloadClaim(approovTokenPayloadClaims, approovConfig);

        if (approovCustomPayloadClaim == null) {

            logger.info("Request approved, but not able to check custom payload claim in the Approov token.");

            // When is `null`, it means we have not met yet a condition to fail the check when the claim is missing.
            // @see getApproovCustomPayloadClaim() for the conditions that will throw an exception.
            return true;
        }

        boolean isMatchingClaims = getClaimHashBase64Encoded(approovHeaderClaim).equals(approovCustomPayloadClaim);

        if (isMatchingClaims) {
            logger.info("Request approved with a valid custom payload claim in the Approov token.");
            return isMatchingClaims;
        }

        // When the request claim values does not match the value in the Approov token custom payload claim, we only
        // abort the request if it is enabled in the Approov configuration.
        if (approovConfig.isToAbortRequestOnInvalidCustomPayloadClaim()) {
            throw new ApproovPayloadAuthenticationException("The Approov header claim value does not match the custom payload claim in the Approov token.");
        }

        logger.info("Request not approved, because the Approov header claim value does not match the custom payload claim in the Approov token.");

        return false;
    }

    private String getApproovCustomPayloadClaim(Claims approovTokenPayloadClaims, ApproovConfig approovConfig) {

        if (approovTokenPayloadClaims == null) {

            if (approovConfig.isToAbortRequestOnInvalidCustomPayloadClaim()) {
                throw new ApproovPayloadAuthenticationException("Approov token payload is null.");
            }

            logger.warn("Approov token payload is null.");

            return null;
        }

        if ( ! approovTokenPayloadClaims.containsKey("pay") ) {

            logger.warn("The custom payload claim is missing in the Approov token.");

            // The Approov custom payload claim is optional, so we cannot throw an exception...
            return null;
        }

        final String approovCustomPayloadClaim = approovTokenPayloadClaims.get("pay").toString();

        if (approovCustomPayloadClaim == null || approovCustomPayloadClaim.trim().equals("")) {

            if (approovConfig.isToAbortRequestOnInvalidCustomPayloadClaim()) {
                throw new ApproovPayloadAuthenticationException("The custom payload claim in the Approov token is null or empty.");
            }

            logger.warn("The custom payload claim in the Approov token is null or empty.");

            return null;
        }

        return approovCustomPayloadClaim;
    }

    private String getClaimHashBase64Encoded(String approovHeaderClaim) {

        final MessageDigest digest;

        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new AuthenticationServiceException(e.getMessage());
        }

        byte[] hash = digest.digest(approovHeaderClaim.getBytes(StandardCharsets.UTF_8));
        String approovHeaderClaimValueBase64Encoded = Base64.encodeBase64String(hash);

        return approovHeaderClaimValueBase64Encoded;
    }
}
