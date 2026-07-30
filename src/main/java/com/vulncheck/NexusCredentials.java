package com.vulncheck;

import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.util.repository.AuthenticationBuilder;

/**
 * Connection details for a private Maven repository.
 *
 * <p>Only the URL is mandatory. Plenty of Nexus and Artifactory proxies serve reads anonymously,
 * and demanding credentials there would force users to invent them. A {@code null} instance of
 * this record means "no private repository at all" — the tool then talks to Maven Central.
 */
public record NexusCredentials(String url, String username, String password) {

    public NexusCredentials {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Nexus URL must not be blank.");
        }
        url = url.endsWith("/") ? url : url + "/";
        username = blankToNull(username);
        password = blankToNull(password);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    public boolean isAuthenticated() {
        return username != null && password != null;
    }

    /** {@code null} for anonymous access — which is how Aether expresses "no authentication". */
    public Authentication toAuthentication() {
        if (!isAuthenticated()) {
            return null;
        }
        return new AuthenticationBuilder()
                .addUsername(username)
                .addPassword(password)
                .build();
    }
}
