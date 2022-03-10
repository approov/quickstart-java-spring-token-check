package com.criticalblue.approov.jwt.authentication;

import java.util.Collection;
import java.util.Collections;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;


/**
 * Validates the Approov Token is signed with the shared secret between Approov and the API server, that have not
 * expired, and optionally also validates the token binding in the Approov token matches the token binding header.
 *
 * @see ApproovAuthenticationProvider
 * @see ApproovSecurityContextRepository
 */
public class ApproovAuthentication implements ApproovJwtAuthentication {

    private static Logger logger = LoggerFactory.getLogger(ApproovAuthentication.class);

    private final ApproovTokenBindingAuthentication approovPayload = new ApproovTokenBindingAuthentication();

    private final ApproovConfig approovConfig;

    private Claims approovTokenPayloadClaims;

    private final String tokenBindingHeader;

    private String approovToken;

    private final boolean checkTokenBinding;

    private boolean isAuthenticated = false;

    private boolean validTokenBinding;

    /**
     * Constructs the Approov Authentication instance that will validate hte Approov token and the token binding.
     *
     * @param approovConfig      Extracted from the .env file in the root of the package.
     * @param approovToken       Extracted from the header `Approov-Token`.
     * @param checkTokenBinding  When to check or not the token binding in the Approov token.
     * @param tokenBindingHeader Extracted by default from the request header `Authorization`.
     */
    ApproovAuthentication(ApproovConfig approovConfig, String approovToken, boolean checkTokenBinding, String tokenBindingHeader) {
        this.approovConfig = approovConfig;
        this.approovToken = approovToken;
        this.checkTokenBinding = checkTokenBinding;
        this.tokenBindingHeader = tokenBindingHeader;
    }

    @Override
    public void checkWith(byte[] approovSecret) throws ApproovAuthenticationException {

        if (approovSecret == null) {
            throw new ApproovAuthenticationException("The Approov secret is null.", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }

        if (approovToken == null) {

            logger.info("Request missing the Approov token.");

            if (approovConfig.isToAbortRequestOnInvalidToken()) {
                throw new ApproovAuthenticationException("The Approov token is null.", HttpStatus.FORBIDDEN.value());
            }

            return;
        }

        approovToken = approovToken.trim();

        if (approovToken.equals("")) {

            if (approovConfig.isToAbortRequestOnInvalidToken()) {
                throw new ApproovAuthenticationException("The Approov token is empty.", HttpStatus.BAD_REQUEST.value());
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
                logger.info("INFO: " + e.getMessage());
                throw new ApproovAuthenticationException(e.getMessage(), HttpStatus.UNAUTHORIZED.value());
            }

            logger.warn("Request approved, but with an invalid Approov token: {}", e.getMessage());

            return;
        }

        if (checkTokenBinding) {
            validTokenBinding = approovPayload.checkClaimMatchesFor(tokenBindingHeader, approovTokenPayloadClaims, approovConfig);
        }

        isAuthenticated = true;
    }

    @Override
    public Claims getApproovTokenPayloadClaims() {
        return approovTokenPayloadClaims;
    }

    @Override
    public boolean isValidTokenBinding() {
        return validTokenBinding;
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
            throw new ApproovAuthenticationException("A new Approov Authentication instance needs to be created to set this.isAuthenticated.", HttpStatus.INTERNAL_SERVER_ERROR.value());
        }
    }

    @Override
    public String getName() {
        return null;
    }
}
