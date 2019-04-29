package com.criticalblue.approov.jwt.authentication;

/**
 * The Approov configuration that is built from the .env file in the root of the package.
 */
final public class ApproovConfig {

    private static ApproovConfig ourInstance = new ApproovConfig();

    private String approovHeaderName = "Approov-Token";

    private final String approovClaimHeaderName;

    private String base64Secret = System.getenv("APPROOV_BASE64_SECRET");

    private boolean toAbortRequestOnInvalidToken;

    private boolean toAbortRequestOnInvalidCustomPayloadClaim;

    /**
     * Constructs the Approov Config singleton with values retrieved from the .env file in the root of the project.
     */
    private ApproovConfig() {
        this.approovClaimHeaderName = retrieveStringValueFromEnv("APPROOV_CLAIM_HEADER_NAME", "Authorization");
        this.toAbortRequestOnInvalidToken = retrieveBooleanValueFromEnv("APPROOV_ABORT_REQUEST_ON_INVALID_TOKEN", true);
        this.toAbortRequestOnInvalidCustomPayloadClaim = retrieveBooleanValueFromEnv("APPROOV_ABORT_REQUEST_ON_INVALID_CUSTOM_PAYLOAD_CLAIM", true);
    }

    public static ApproovConfig getInstance() {
        return ourInstance;
    }

    String getApproovHeaderName() {
        return approovHeaderName;
    }

    String getApproovClaimHeaderName() {
        return approovClaimHeaderName;
    }

    String getBase64Secret() {
        return base64Secret;
    }

    boolean isToAbortRequestOnInvalidToken() {
        return toAbortRequestOnInvalidToken;
    }

    boolean isToAbortRequestOnInvalidCustomPayloadClaim() {
        return toAbortRequestOnInvalidCustomPayloadClaim;
    }

    private String retrieveStringValueFromEnv(String key, String defaultValue) {

        String value = System.getenv(key);

        if (value == null) {
            return defaultValue;
        }

        return value.trim();
    }

    private boolean retrieveBooleanValueFromEnv(String key, boolean defaultValue) {

        String value = System.getenv(key);

        if (value == null) {
            return defaultValue;
        }

        return value.trim().equalsIgnoreCase("true");
    }
}
