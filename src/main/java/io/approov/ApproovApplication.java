package io.approov;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
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
    private static final String DIGEST_HEADER = "Content-Digest";
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
        if (!hasText(secret)) {
            LOGGER.error("APPROOV_BASE64URL_SECRET environment variable is not set");
            throw new IllegalStateException("APPROOV_BASE64URL_SECRET environment variable is not set");
        }
        return Base64.getUrlDecoder().decode(secret.trim());       
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
                @RequestHeader(value = DIGEST_HEADER, required = false) String contentDigest) {
            Map<String, Object> response = infoPayload(
                    "Protected endpoint '/token-double-binding'; dual token binding enforced.");
            response.put("authorizationHeaderPresent", hasText(authorization));
            response.put("contentDigestHeaderPresent", hasText(contentDigest));
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
    static class SecurityConfig extends WebSecurityConfigurerAdapter {

        private final AuthenticationEntryPoint authEntryPoint = new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED);

        @Bean
        public UserDetailsService userDetailsService() {
            return new InMemoryUserDetailsManager();
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http.csrf().disable()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                    .authorizeRequests()
                    .antMatchers(
                            "/",
                            "/unprotected",
                            "/approov-state",
                            "/approov/enable",
                            "/approov/disable",
                            "/token-binding/enable",
                            "/token-binding/disable")
                    .permitAll()
                    .anyRequest()
                    .authenticated()
                    .and()
                    .exceptionHandling()
                    .authenticationEntryPoint(authEntryPoint)
                    .and()
                    .addFilterBefore(
                            new ApproovTokenVerifier(authEntryPoint),
                            UsernamePasswordAuthenticationFilter.class);
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

            if (!isApproovEnabled()) {
                SecurityContextHolder.getContext().setAuthentication(disabledAuthentication());
                filterChain.doFilter(request, response);
                return;
            }

            String rawToken = request.getHeader(APPROOV_HEADER);
            if (!hasText(rawToken)) {
                unauthorized(request, response);
                return;
            }

            try {
                Claims claims = verifyApproovToken(rawToken.trim());
                String path = request.getRequestURI();

                if (needsBindingCheck(path) && isTokenBindingEnabled()) {
                    String bindingValue = extractBindingValue(path, request);
                    if (!hasText(bindingValue) || !isBindingValid(bindingValue, claims)) {
                        unauthorized(request, response);
                        return;
                    }
                }

                Authentication authentication = new UsernamePasswordAuthenticationToken(
                        "approov-token", null, Collections.emptyList());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                filterChain.doFilter(request, response);
            } catch (JwtException | IllegalArgumentException e) {
                LOGGER.error("Approov token verification failed: {}", e.getMessage());
                unauthorized(request, response);
            }
        }

        private void unauthorized(
                HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
            entryPoint.commence(
                    request,
                    response,
                    new BadCredentialsException("Approov authentication failed."));
        }

        private Claims verifyApproovToken(String token) {
            Jws<Claims> claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(approovSecret()))
                    .build()
                    .parseClaimsJws(token);
            validateExpiration(claims.getBody());
            return claims.getBody();
        }

        private boolean needsBindingCheck(String path) {
            return "/token-binding".equals(path) || "/token-double-binding".equals(path);
        }

        private String extractBindingValue(String path, HttpServletRequest request) {
            if ("/token-binding".equals(path)) {
                return trimOrNull(request.getHeader(AUTH_HEADER));
            }
            String authorization = trimOrNull(request.getHeader(AUTH_HEADER));
            String digest = trimOrNull(request.getHeader(DIGEST_HEADER));
            if (!hasText(authorization) || !hasText(digest)) {
                return null;
            }
            return authorization + digest;
        }

        private boolean isBindingValid(String bindingValue, Claims claims) {
            String expected = claims.get("pay", String.class);
            if (!hasText(expected)) {
                return false;
            }
            String computed = hashBase64Url(bindingValue);
            return expected.trim().equals(computed);
        }

        private String hashBase64Url(String value) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
                return Base64.getEncoder().encodeToString(hash);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 not available", e);
            }
        }

        private Authentication disabledAuthentication() {
            return new UsernamePasswordAuthenticationToken(
                    "approov-disabled", null, Collections.emptyList());
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

        private String trimOrNull(String value) {
            return value == null ? null : value.trim();
        }
    }
}