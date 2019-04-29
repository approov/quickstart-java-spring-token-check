package com.criticalblue.approov.jwt.authentication;

import java.util.Collection;
import java.util.Collections;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;


/**
 * Validates the Approov Token is signed with the shared secret between Approov and the API server, that have not
 * expired, and optionally that the custom payload claim matches the request claim.
 *
 * @see ApproovAuthenticationProvider
 * @see ApproovSecurityContextRepository
 */
public class ApproovAuthentication implements ApproovJwtAuthentication {

    private static Logger logger = LoggerFactory.getLogger(ApproovAuthentication.class);

    private final ApproovPayloadAuthentication approovPayload = new ApproovPayloadAuthentication();

    private final ApproovConfig approovConfig;

    private Claims approovTokenPayloadClaims;

    private final String approovHeaderClaim;

    private String approovToken;

    private final boolean checkApproovHeaderClaim;

    private boolean isAuthenticated = false;

    private boolean validApproovHeaderClaim;

    /**
     * Constructs the Approov Authentication instance that will validate hte Approov token and custom payload claim.
     *
     * @param approovConfig           Extracted from the .env file in the root of the package.
     * @param approovToken            Extracted from the header `approov-token`.
     * @param checkApproovHeaderClaim When to check or not the custom payload claim in the Approov token.
     * @param approovHeaderClaim      Extracted by default from the header `Authorization`.
     */
    ApproovAuthentication(ApproovConfig approovConfig, String approovToken, boolean checkApproovHeaderClaim, String approovHeaderClaim) {
        this.approovConfig = approovConfig;
        this.approovToken = approovToken;
        this.checkApproovHeaderClaim = checkApproovHeaderClaim;
        this.approovHeaderClaim = approovHeaderClaim;
    }

    @Override
    public void checkWith(byte[] approovSecret) throws AuthenticationException {

        if (approovSecret == null) {
            throw new ApproovAuthenticationException("The Approov secret is null.");
        }

        if (approovToken == null) {

            if (approovConfig.isToAbortRequestOnInvalidToken()) {
                throw new ApproovAuthenticationException("The Approov token is null.");
            }

            return;
        }

        approovToken = approovToken.trim();

        if (approovToken.equals("")) {

            if (approovConfig.isToAbortRequestOnInvalidToken()) {
                throw new ApproovAuthenticationException("The Approov token is empty.");
            }

            return;
        }

        try {

            approovTokenPayloadClaims = Jwts.parser()
                .setSigningKey(approovSecret)
                .parseClaimsJws(approovToken)
                .getBody();

            logger.info("Request approved with a valid Approov token.");

        } catch (JwtException e) {

            if (approovConfig.isToAbortRequestOnInvalidToken()) {
                throw new ApproovAuthenticationException(e.getMessage());
            }

            logger.warn("Request approved, but with an invalid Approov token: {}", e.getMessage());

            return;
        }

        if (checkApproovHeaderClaim) {
            validApproovHeaderClaim = approovPayload.checkClaimMatchesFor(approovHeaderClaim, approovTokenPayloadClaims, approovConfig);
        }

        isAuthenticated = true;
    }

    @Override
    public Claims getApproovTokenPayloadClaims() {
        return approovTokenPayloadClaims;
    }

    @Override
    public boolean isValidApproovHeaderClaim() {
        return validApproovHeaderClaim;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public Object getCredentials() {
        return approovToken;
    }

    @Override
    public Object getDetails() {
        return approovTokenPayloadClaims;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if (isAuthenticated) {
            throw new ApproovAuthenticationException("A new Approov Authentication instance needs to be created to set this.isAuthenticated.");
        }
    }

    @Override
    public String getName() {
        return null;
    }
}
