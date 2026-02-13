package io.approov;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.OncePerRequestFilter;

@SpringBootApplication
public class ApproovApplication {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApproovApplication.class);
    private static final String APPROOV_HEADER = "Approov-Token";
    private static final String AUTH_HEADER = "Authorization";
    private static final String SESSION_ID_HEADER = "SessionId";
    private static final String PLACEHOLDER_SECRET = "approov_base64url_secret_here";
    private static final AtomicBoolean APPROOV_ENABLED = new AtomicBoolean(true);
    private static final AtomicBoolean TOKEN_BINDING_ENABLED = new AtomicBoolean(true);
    private static final byte[] APPROOV_SECRET = loadApproovSecret();

    private static boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    public static void main(String[] args) {
        SpringApplication.run(ApproovApplication.class, args);
    }

    static boolean isApproovEnabled() {
        return APPROOV_ENABLED.get();
    }

    static boolean isTokenBindingEnabled() {
        return TOKEN_BINDING_ENABLED.get();
    }

    static void enableApproov() {
        APPROOV_ENABLED.set(true);
        TOKEN_BINDING_ENABLED.set(true);
    }

    static void disableApproov() {
        APPROOV_ENABLED.set(false);
        TOKEN_BINDING_ENABLED.set(false);
    }

    static byte[] approovSecret() {
        return APPROOV_SECRET;
    }

    private static byte[] loadApproovSecret() {
        String secret = System.getenv("APPROOV_BASE64URL_SECRET");
        if (!hasText(secret) || PLACEHOLDER_SECRET.equals(secret.trim())) {
            LOGGER.error("Required secret is not set");
            throw new IllegalStateException("Required secret is not set");
        }
        try {
            return Base64.getUrlDecoder().decode(secret.trim());
        } catch (IllegalArgumentException e) {
            LOGGER.error("Required secret is invalid");
            throw new IllegalStateException("Required secret is invalid", e);
        }
    }

    @RestController
    @RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    static class ApproovController {

        @GetMapping("/")
        public Map<String, Object> home() {
            return infoPayload("Approov demo API is running on port 8080.");
        }

        @GetMapping("/approov-state")
        public ResponseEntity<Map<String, Object>> approovState() {
            Map<String, Object> body = statePayload();
            return ResponseEntity.ok(body);
        }

        @PostMapping("/approov/enable")
        public Map<String, Object> enableApproovEndpoint() {
            enableApproov();
            return statePayload();
        }

        @PostMapping("/approov/disable")
        public Map<String, Object> disableApproovEndpoint() {
            disableApproov();
            return statePayload();
        }

        @PostMapping("/token-binding/enable")
        public Map<String, Object> enableTokenBindingEndpoint() {
            TOKEN_BINDING_ENABLED.set(true);
            return statePayload();
        }

        @PostMapping("/token-binding/disable")
        public Map<String, Object> disableTokenBindingEndpoint() {
            TOKEN_BINDING_ENABLED.set(false);
            return statePayload();
        }

        @GetMapping("/unprotected")
        public Map<String, Object> unprotected() {
            return infoPayload("Unprotected endpoint '/unprotected'; no Approov checks performed.");
        }

        @GetMapping("/token-check")
        public Map<String, Object> tokenCheck() {
            return infoPayload("Protected endpoint '/token-check'; Approov token verified.");
        }

        @GetMapping("/token-binding")
        public Map<String, Object> tokenBinding(
                @RequestHeader(value = AUTH_HEADER, required = false) String authorization) {
            Map<String, Object> response = infoPayload(
                    "Protected endpoint '/token-binding'; Approov token binding enforced.");
            response.put("authorizationHeaderPresent", hasText(authorization));
            return response;
        }

        @GetMapping("/token-double-binding")
        public Map<String, Object> tokenDoubleBinding(
                @RequestHeader(value = AUTH_HEADER, required = false) String authorization,
                @RequestHeader(value = SESSION_ID_HEADER, required = false) String sessionId) {
            Map<String, Object> response = infoPayload(
                    "Protected endpoint '/token-double-binding'; dual token binding enforced.");
            response.put("authorizationHeaderPresent", hasText(authorization));
            response.put("sessionIdHeaderPresent", hasText(sessionId));
            return response;
        }

        private Map<String, Object> statePayload() {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("approovEnabled", isApproovEnabled());
            body.put("tokenBindingEnabled", isTokenBindingEnabled());
            return body;
        }

        private Map<String, Object> infoPayload(String details) {
            Map<String, Object> body = statePayload();
            body.put("details", details);
            return body;
        }
    }

    @Configuration
    @EnableWebSecurity
    static class SecurityConfig {

        private final AuthenticationEntryPoint authEntryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

        @Bean
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager();
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.csrf(csrf -> csrf.disable())
                    .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth -> auth
                            .requestMatchers(
                                    "/",
                                    "/unprotected",
                                    "/approov-state",
                                    "/approov/enable",
                                    "/approov/disable",
                                    "/token-binding/enable",
                                    "/token-binding/disable")
                            .permitAll()
                            .anyRequest()
                            .authenticated())
                    .exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(authEntryPoint))
                    .addFilterBefore(
                            new ApproovTokenVerifier(authEntryPoint),
                            AuthorizationFilter.class);
            return http.build();
        }
    }

    /**
     * Stateless filter that validates the Approov token (and bindings when enabled)
     * before protected endpoints.
     */
    static class ApproovTokenVerifier extends OncePerRequestFilter {

        private static final Set<String> APPROOV_PROTECTED_PATHS = Collections.unmodifiableSet(
                new java.util.HashSet<>(Arrays.asList(
                        "/token-check", "/token-binding", "/token-double-binding")));

        private final AuthenticationEntryPoint entryPoint;
        private final ApproovTokenValidator validator = new ApproovTokenValidator();

        ApproovTokenVerifier(AuthenticationEntryPoint entryPoint) {
            this.entryPoint = entryPoint;
        }

        @Override
        protected boolean shouldNotFilter(HttpServletRequest request) {
            String path = request.getRequestURI();
            return path == null || !APPROOV_PROTECTED_PATHS.contains(path);
        }

        @Override
        protected void doFilterInternal(
                HttpServletRequest request,
                HttpServletResponse response,
                FilterChain filterChain) throws ServletException, IOException {
            String path = request.getRequestURI();
            List<String> requiredHeaders = validator.requiredHeadersForPath(path);

            if (!isApproovEnabled()) {
                SecurityContextHolder.getContext().setAuthentication(disabledAuthentication());
                filterChain.doFilter(request, response);
                logResponseIfNeeded(request, response, "approov_disabled", requiredHeaders);
                return;
            }

            ValidationResult validation = validator.validate(path, request::getHeader);
            if (!validation.isSuccessful()) {
                logValidationFailure(request, validation);
                SecurityContextHolder.clearContext();
                commenceUnauthorized(request, response);
                return;
            }

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    "approov-token", null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
            logResponseIfNeeded(request, response, "approov_ok", validation.requiredHeaders());
        }

        private void logValidationFailure(HttpServletRequest request, ValidationResult validation) {
            ValidationError error = validation.error();
            if (error == null) {
                return;
            }
            logRequest(
                    request,
                    HttpStatus.UNAUTHORIZED.value(),
                    "approov_failed:" + error.reason(),
                    validation.requiredHeaders(),
                    error.message(),
                    error.exception());
        }

        private void commenceUnauthorized(HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException {
            entryPoint.commence(
                    request,
                    response,
                    new BadCredentialsException("Approov authentication failed."));
        }

        private void logResponseIfNeeded(
                HttpServletRequest request,
                HttpServletResponse response,
                String successSummary,
                List<String> requiredHeaders) {
            int status = response.getStatus();
            if (status == HttpStatus.UNAUTHORIZED.value()) {
                logRequest(
                        request,
                        status,
                        "approov_failed:downstream_unauthorized",
                        requiredHeaders,
                        null,
                        null);
                return;
            }
            logRequest(request, status, successSummary, requiredHeaders, null, null);
        }

        private void logRequest(
                HttpServletRequest request,
                int status,
                String summary,
                List<String> requiredHeaders,
                String error,
                String exception) {
            if (status != HttpStatus.OK.value() && status != HttpStatus.UNAUTHORIZED.value()) {
                return;
            }
            String method = request.getMethod();
            String path = request.getRequestURI();
            String ip = request.getRemoteAddr();
            int port = request.getServerPort();
            String flags = String.format(
                    "{\"approovEnabled\":%s,\"tokenBindingEnabled\":%s}",
                    isApproovEnabled(),
                    isTokenBindingEnabled());
            String requiredHeadersValue = formatRequiredHeaders(requiredHeaders);
            if (hasText(error) || hasText(exception)) {
                LOGGER.warn(
                        "http.request.completed \"summary\":\"{}\",\"method\":\"{}\",\"path\":\"{}\","
                                + "\"status\":{},\"ip\":\"{}\",\"port\":{}, {} \"required_headers\":{} "
                                + "\"error\":\"{}\" \"exception\":\"{}\"",
                        summary,
                        method,
                        path,
                        status,
                        ip,
                        port,
                        flags,
                        requiredHeadersValue,
                        error,
                        exception);
            } else {
                LOGGER.info(
                        "http.request.completed \"summary\":\"{}\",\"method\":\"{}\",\"path\":\"{}\","
                                + "\"status\":{},\"ip\":\"{}\",\"port\":{}, {} \"required_headers\":{}",
                        summary,
                        method,
                        path,
                        status,
                        ip,
                        port,
                        flags,
                        requiredHeadersValue);
            }
        }

        private String formatRequiredHeaders(List<String> headers) {
            if (headers == null || headers.isEmpty()) {
                return "[]";
            }
            StringBuilder builder = new StringBuilder("[");
            for (int i = 0; i < headers.size(); i++) {
                if (i > 0) {
                    builder.append(',');
                }
                builder.append('"').append(headers.get(i)).append('"');
            }
            builder.append(']');
            return builder.toString();
        }

        private Authentication disabledAuthentication() {
            return new UsernamePasswordAuthenticationToken(
                    "approov-disabled", null, Collections.emptyList());
        }

        private static String trimOrNull(String value) {
            return value == null ? null : value.trim();
        }

        static final class ApproovTokenValidator {

            ValidationResult validate(String path, Function<String, String> headerProvider) {
                List<String> bindingHeaders = bindingHeadersForPath(path);
                List<String> requiredHeaders = requiredHeadersForRequest(bindingHeaders);

                String rawToken = trimOrNull(headerProvider.apply(APPROOV_HEADER));
                if (!hasText(rawToken)) {
                    return ValidationResult.failure(requiredHeaders, "missing_approov_token", null, null);
                }

                Claims claims;
                try {
                    claims = verifyApproovToken(rawToken);
                } catch (JwtException | IllegalArgumentException e) {
                    return ValidationResult.failure(
                            requiredHeaders,
                            "token_verification_failed",
                            e.getMessage(),
                            e.getClass().getSimpleName());
                }

                if (isTokenBindingEnabled() && !bindingHeaders.isEmpty()) {
                    String bindingValue = extractBindingValue(headerProvider, bindingHeaders);
                    if (!hasText(bindingValue)) {
                        return ValidationResult.failure(requiredHeaders, "missing_binding_header", null, null);
                    }
                    if (!isBindingValid(bindingValue, claims)) {
                        return ValidationResult.failure(requiredHeaders, "binding_mismatch", null, null);
                    }
                }
                return ValidationResult.success(requiredHeaders);
            }

            List<String> requiredHeadersForPath(String path) {
                return requiredHeadersForRequest(bindingHeadersForPath(path));
            }

            private Claims verifyApproovToken(String token) {
                Jws<Claims> claims = Jwts.parser()
                        .verifyWith(Keys.hmacShaKeyFor(approovSecret()))
                        .build()
                        .parseSignedClaims(token);
                validateExpiration(claims.getPayload());
                return claims.getPayload();
            }

            private List<String> bindingHeadersForPath(String path) {
                if ("/token-binding".equals(path)) {
                    return List.of(AUTH_HEADER);
                }
                if ("/token-double-binding".equals(path)) {
                    return List.of(AUTH_HEADER, SESSION_ID_HEADER);
                }
                return Collections.emptyList();
            }

            private List<String> requiredHeadersForRequest(List<String> bindingHeaders) {
                if (!isTokenBindingEnabled() || bindingHeaders.isEmpty()) {
                    return List.of(APPROOV_HEADER);
                }
                List<String> headers = new ArrayList<>(1 + bindingHeaders.size());
                headers.add(APPROOV_HEADER);
                headers.addAll(bindingHeaders);
                return headers;
            }

            private String extractBindingValue(Function<String, String> headerProvider, List<String> bindingHeaders) {
                if (bindingHeaders.isEmpty()) {
                    return null;
                }
                StringBuilder combined = new StringBuilder();
                for (String header : bindingHeaders) {
                    String value = trimOrNull(headerProvider.apply(header));
                    if (!hasText(value)) {
                        return null;
                    }
                    combined.append(value);
                }
                return combined.toString();
            }

            private boolean isBindingValid(String bindingValue, Claims claims) {
                String expected = claims.get("pay", String.class);
                if (!hasText(expected)) {
                    return false;
                }
                String computed = hashBase64(bindingValue);
                return MessageDigest.isEqual(
                        expected.trim().getBytes(StandardCharsets.UTF_8),
                        computed.getBytes(StandardCharsets.UTF_8));
            }

            private String hashBase64(String value) {
                try {
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
                    return Base64.getEncoder().encodeToString(hash);
                } catch (NoSuchAlgorithmException e) {
                    throw new IllegalStateException("SHA-256 not available", e);
                }
            }

            private void validateExpiration(Claims claims) {
                Date expiration = claims.getExpiration();
                if (expiration == null) {
                    throw new JwtException("Approov token missing expiration.");
                }
                if (expiration.before(new Date())) {
                    throw new JwtException("Approov token expired.");
                }
            }
        }

        static final class ValidationResult {

            private final List<String> requiredHeaders;
            private final ValidationError error;

            private ValidationResult(List<String> requiredHeaders, ValidationError error) {
                this.requiredHeaders = List.copyOf(requiredHeaders);
                this.error = error;
            }

            static ValidationResult success(List<String> requiredHeaders) {
                return new ValidationResult(requiredHeaders, null);
            }

            static ValidationResult failure(
                    List<String> requiredHeaders,
                    String reason,
                    String message,
                    String exception) {
                return new ValidationResult(requiredHeaders, new ValidationError(reason, message, exception));
            }

            boolean isSuccessful() {
                return error == null;
            }

            List<String> requiredHeaders() {
                return requiredHeaders;
            }

            ValidationError error() {
                return error;
            }
        }

        static final class ValidationError {

            private final String reason;
            private final String message;
            private final String exception;

            ValidationError(String reason, String message, String exception) {
                this.reason = reason;
                this.message = message;
                this.exception = exception;
            }

            String reason() {
                return reason;
            }

            String message() {
                return message;
            }

            String exception() {
                return exception;
            }
        }
    }
}
