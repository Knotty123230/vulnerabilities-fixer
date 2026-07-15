package com.vulncheck;

public record SonatypeCredentials(
        String serverUrl,
        String applicationId,
        String sonatypeUsername,
        String sonatypePassword
) {
    public SonatypeCredentials {
        serverUrl = requireNonBlank(serverUrl, "Sonatype server URL");
        applicationId = requireNonBlank(applicationId, "Sonatype application ID");
        sonatypeUsername = requireNonBlank(sonatypeUsername, "Sonatype username");
        sonatypePassword = requireNonBlank(sonatypePassword, "Sonatype password");
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank.");
        }
        return value;
    }
}
