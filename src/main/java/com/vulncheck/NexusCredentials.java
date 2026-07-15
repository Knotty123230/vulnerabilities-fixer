package com.vulncheck;

public record NexusCredentials(String url, String username, String password) {

    public NexusCredentials {
        url = requireNonBlank(url, "Nexus URL");
        username = requireNonBlank(username, "Nexus username");
        password = requireNonBlank(password, "Nexus password");
    }

    private static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(fieldName + " must not be blank.");
        }
        return value;
    }
}
