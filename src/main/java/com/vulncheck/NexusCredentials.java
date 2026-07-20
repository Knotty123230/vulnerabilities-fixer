package com.vulncheck;

import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.util.repository.AuthenticationBuilder;

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

    public Authentication toAuthentication() {
        return new AuthenticationBuilder()
                .addUsername(username)
                .addPassword(password)
                .build();
    }
}
