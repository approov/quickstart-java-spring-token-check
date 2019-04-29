package com.criticalblue.approov.jwt.authentication;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;


/**
 * When a failure occurs during the Approov token authentication process, an exception is thrown and Spring redirects
 * to an authentication entry point, that have been configured in the Sring security to be this one.
 *
 * @see com.criticalblue.approov.jwt.WebSecurityConfig
 * @see ApproovAuthentication
 * @see ApproovPayloadAuthentication
 */
public class ApproovAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final static Logger logger = LoggerFactory.getLogger(ApproovAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        logger.debug("Rejected a request in an endpoint protected by an Approov Token.");
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    }
}
