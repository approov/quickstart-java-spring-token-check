package com.criticalblue.approov.jwt.authentication;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;


/**
 * When a failure occurs during the Approov token authentication process, an exception is thrown and Spring redirects
 * to an authentication entry point, that have been configured in the Sring security to be this one.
 *
 * @see com.criticalblue.approov.jwt.WebSecurityConfig
 * @see ApproovAuthentication
 * @see ApproovTokenBindingAuthentication
 */
public class ApproovAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final static Logger logger = LoggerFactory.getLogger(ApproovAuthenticationEntryPoint.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        int httpStatusCode = HttpStatus.BAD_REQUEST.value();

        if (authException instanceof ApproovException) {
            httpStatusCode = ((ApproovException) authException).getHttpStatusCode();
        }

        final String httpStatusMessage = String.valueOf(HttpStatus.valueOf(httpStatusCode));
        final String exceptionType = String.valueOf(authException.getClass());
        final String exceptionMessage = authException.getMessage();

        logger.info(httpStatusMessage + " | " + exceptionType + " | " + exceptionMessage);
        response.sendError(httpStatusCode);
    }
}
