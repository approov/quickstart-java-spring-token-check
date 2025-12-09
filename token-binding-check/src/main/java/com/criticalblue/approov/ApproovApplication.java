package com.criticalblue.approov;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Single-file Spring Boot app exposing Approov-protected endpoints.
 * Only the essential Approov token + binding checks are implemented here.
 */
@SpringBootApplication
@RestController
@EnableWebSecurity
public class ApproovApplication {

    private static final Logger log = LoggerFactory.getLogger(ApproovApplication.class);

    private static final AtomicBoolean approovEnabled = new AtomicBoolean(true);
    private static final AtomicBoolean tokenBindingEnabled = new AtomicBoolean(true);

    private final Key signingKey;

    public ApproovApplication() {
        this.signingKey = resolveSigningKey();
    }

    public static void main(String[] args) {
        SpringApplication app = new SpringApplication(ApproovApplication.class);
        Map<String, Object> props = new HashMap<>();
        props.put("server.port", 8080);
        props.put("spring.main.banner-mode", "off");
        props.put("logging.level.root", "INFO");
        app.setDefaultProperties(props);
        app.run(args);
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests(auth -> auth.anyRequest().permitAll())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }

    // region Public endpoints

    @GetMapping("/unprotected")
    public Map<String, Object> unprotected() {
        return message("Unprotected endpoint reached at " + Instant.now());
    }

    @GetMapping("/token-check")
    public Map<String, Object> tokenCheck(
        @RequestHeader(value = "Approov-Token", required = false) String token
    ) {
        Claims claims = enforceToken(token);
        log.debug("Token-check passed for jti={}", claims != null ? claims.getId() : "skipped");
        return message("Token check passed");
    }

    @GetMapping("/token-binding")
    public Map<String, Object> tokenBinding(
        @RequestHeader(value = "Approov-Token", required = false) String token,
        @RequestHeader(value = "Authorization", required = false) String authorization
    ) {
        Claims claims = enforceToken(token);
        enforceBinding(claims, Collections.singletonList(authorization));
        return message("Token binding passed");
    }

    @GetMapping("/token-double-binding")
    public Map<String, Object> tokenDoubleBinding(
        @RequestHeader(value = "Approov-Token", required = false) String token,
        @RequestHeader(value = "Authorization", required = false) String authorization,
        @RequestHeader(value = "Content-Digest", required = false) String contentDigest
    ) {
        Claims claims = enforceToken(token);
        enforceBinding(claims, Arrays.asList(authorization, contentDigest));
        return message("Token double binding passed");
    }

    @GetMapping("/approov-state")
    public Map<String, Object> approovState() {
        Map<String, Object> state = new HashMap<>();
        state.put("approovEnabled", approovEnabled.get());
        state.put("tokenBindingEnabled", tokenBindingEnabled.get());
        state.put("timestamp", Instant.now().toString());
        return state;
    }

    @PostMapping("/approov/enable")
    public Map<String, Object> enableApproov() {
        approovEnabled.set(true);
        tokenBindingEnabled.set(true); // enabling approov re-enables binding
        log.info("Approov checks enabled");
        return approovState();
    }

    @PostMapping("/approov/disable")
    public Map<String, Object> disableApproov() {
        approovEnabled.set(false);
        tokenBindingEnabled.set(false); // disabling approov disables binding too
        log.info("Approov checks disabled");
        return approovState();
    }

    @PostMapping("/token-binding/enable")
    public Map<String, Object> enableBinding() {
        tokenBindingEnabled.set(true);
        log.info("Token binding enabled");
        return approovState();
    }

    @PostMapping("/token-binding/disable")
    public Map<String, Object> disableBinding() {
        tokenBindingEnabled.set(false);
        log.info("Token binding disabled");
        return approovState();
    }

    // endregion

    // region Approov helpers

    /**
     * Validates signature/claims when Approov is enabled.
     */
    private Claims enforceToken(String token) {
        if (!approovEnabled.get()) {
            return null;
        }

        if (token == null || token.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing Approov-Token header");
        }

        Claims claims;
        try {
            claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
        } catch (JwtException | IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Approov token");
        }

        Date expiry = claims.getExpiration();
        if (expiry == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Approov token missing expiry");
        }
        return claims;
    }

    /**
     * Verifies the binding hash ("pay" claim) when token binding is enabled.
     */
    private void enforceBinding(Claims claims, List<String> bindingValues) {
        if (!approovEnabled.get() || !tokenBindingEnabled.get()) {
            return;
        }

        if (bindingValues.stream().anyMatch(v -> v == null || v.isEmpty())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Missing token binding header");
        }

        String expectedBinding = claims.get("pay", String.class);
        if (expectedBinding == null || expectedBinding.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token missing binding claim");
        }

        String bindingData = String.join("", bindingValues);
        String computedBinding = computeBinding(bindingData);
        if (!bindingsMatch(expectedBinding, computedBinding) && !bindingsMatch(expectedBinding, computeBindingStd(bindingData))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token binding mismatch");
        }
    }

    private String computeBinding(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    // Approov CLI may emit bindings using standard Base64; accept both to stay compatible.
    private String computeBindingStd(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().withoutPadding().encodeToString(hashed);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private boolean bindingsMatch(String expected, String computed) {
        return normalizeBinding(expected).equals(normalizeBinding(computed));
    }

    private String normalizeBinding(String value) {
        if (value == null) {
            return "";
        }
        String noPad = value.replace("=", "");
        return noPad.replace('-', '+').replace('_', '/');
    }

    private Key resolveSigningKey() {
        String secret = System.getenv("APPROOV_BASE64_SECRET");
        if (secret == null || secret.trim().isEmpty()) {
            secret = System.getProperty("APPROOV_BASE64_SECRET");
        }
        if (secret == null || secret.trim().isEmpty()) {
            secret = readDotEnvSecret();
        }
        if (secret == null || secret.trim().isEmpty()) {
            secret = "h+CX0tOzdAAR9l15bWAqvq7w9olk66daIH+Xk+IAHhVVHszjDzeGobzNnqyRze3lw/WVyWrc2gZfh3XXfBOmww==";
            log.warn("APPROOV_BASE64_SECRET not set; using demo secret");
        }
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret.trim()));
    }

    private String readDotEnvSecret() {
        java.nio.file.Path path = java.nio.file.Paths.get(".env");
        if (!java.nio.file.Files.exists(path)) {
            return null;
        }
        try {
            return java.nio.file.Files.lines(path)
                .map(String::trim)
                .filter(line -> !line.startsWith("#"))
                .filter(line -> line.startsWith("APPROOV_BASE64_SECRET="))
                .map(line -> line.substring("APPROOV_BASE64_SECRET=".length()))
                .filter(v -> !v.isEmpty())
                .findFirst()
                .orElse(null);
        } catch (IOException e) {
            log.warn("Unable to read .env file for APPROOV_BASE64_SECRET", e);
            return null;
        }
    }

    private Map<String, Object> message(String msg) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("message", msg);
        return payload;
    }

    // endregion
}
