package com.criticalblue.approov.jwt.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * Used to setup the Approov Authentication Context when configuring the Spring framework security.
 *
 * @see com.criticalblue.approov.jwt.WebSecurityConfig
 */
public class ApproovSecurityContextRepository implements SecurityContextRepository {

    private final boolean checkApproovHeaderClaim;

    private String approovToken = null;

    final private ApproovConfig approovConfig;

    /**
     * Constructs with an instance of the Approov configuration, and with a boolean flag to indicate if is to check the
     * custom payload claim in the Approov token.
     *
     * @param approovConfig           Extracted from the .env file in the root of the project.
     * @param checkApproovHeaderClaim When to check or not the custom payload claim in the Approov token.
     */
    public ApproovSecurityContextRepository(ApproovConfig approovConfig, boolean checkApproovHeaderClaim) {
        this.approovConfig = approovConfig;
        this.checkApproovHeaderClaim = checkApproovHeaderClaim;
    }

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {

        String approovHeaderClaim = null;

        HttpServletRequest request = requestResponseHolder.getRequest();

        SecurityContext context = SecurityContextHolder.createEmptyContext();

        approovToken = request.getHeader(approovConfig.getApproovHeaderName());

        // When no Approov token is provided we must be in an endpoint not protected by Approov, otherwise the Approov
        // token is missing in the header of the request.
        if (approovToken == null) {

            // returning an empty security context in an endpoint protected by Approov, will cause Spring to later throw
            // this exception:
            //  org.springframework.security.access.AccessDeniedException: Access is denied
            return context;
        }

        if (checkApproovHeaderClaim) {
            approovHeaderClaim = getApproovHeaderClaimFrom(request);
        }

        Authentication approovAuthentication = new ApproovAuthentication(approovConfig, approovToken, checkApproovHeaderClaim, approovHeaderClaim);
        context.setAuthentication(approovAuthentication);

        return context;
    }

    private String getApproovHeaderClaimFrom(HttpServletRequest request) {

        final String headerName = approovConfig.getApproovClaimHeaderName();

        if (headerName == null) {
            return null;
        }

        final String approovHeaderClaim = request.getHeader(headerName);

        if (approovHeaderClaim == null) {
            return null;
        }

        if (approovHeaderClaim.toLowerCase().startsWith("bearer")) {

            String[] parts = approovHeaderClaim.split(" ");

            if (parts.length < 2) {
                return null;
            }

            return parts[1].trim();
        }

        return approovHeaderClaim.trim();
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        return approovToken != null;
    }
}
