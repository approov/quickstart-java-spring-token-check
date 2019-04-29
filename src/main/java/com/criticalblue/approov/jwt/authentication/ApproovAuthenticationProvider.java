package com.criticalblue.approov.jwt.authentication;

import org.apache.tomcat.util.codec.binary.Base64;

import org.jetbrains.annotations.NotNull;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * Used to configure the Spring framework security with the trigger for the Approov Authentication.
 *
 * @see com.criticalblue.approov.jwt.WebSecurityConfig
 * @see ApproovAuthentication
 */
public class ApproovAuthenticationProvider implements AuthenticationProvider {

    private final byte[] approovSecret;

    /**
     * Constructs the Approov Authentication provider with an instance of the Approov config.
     *
     * @param approovConfig Extracted from the .env file in the root of the package.
     */
    public ApproovAuthenticationProvider(ApproovConfig approovConfig) {
        this.approovSecret = Base64.decodeBase64(approovConfig.getBase64Secret());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return ApproovJwtAuthentication.class.isAssignableFrom(authentication);
    }

    @Override
    public Authentication authenticate(@NotNull Authentication authentication) throws AuthenticationException {

        if (!supports(authentication.getClass())) {
            return null;
        }

        ApproovJwtAuthentication approovTokenAuthentication = (ApproovJwtAuthentication) authentication;

        approovTokenAuthentication.checkWith(approovSecret);

        return approovTokenAuthentication;
    }
}
