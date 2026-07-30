package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QuarantineDetectorTest {

    /** The exact message Nexus Repository Firewall produced in a real build. */
    private static final String REAL_MESSAGE =
            "Could not transfer artifact org.jetbrains.kotlinx:kotlinx-metadata-jvm:jar:0.9.0 "
                    + "from/to nexus (https://nexus.privatbank.ua/repository/maven-public/): "
                    + "status code: 403, reason phrase: -------------------->>> REQUESTED ITEM IS "
                    + "QUARANTINED -------------------->>> FOR DETAILS SEE ------>>> "
                    + "https://iq.nexus.privatbank.ua/ui/links/firewall/repositories/"
                    + "quarantinedComponent/MzdhODY4NGRiODE4NDE0YTkwMmU0ZmIwMDA5ZjI0Njk <<<------ (403)";

    @Test
    @DisplayName("recognises a quarantine and extracts the IQ link")
    void detectsRealQuarantineMessage() {
        // Aether buries the transport failure several layers deep, as it does in a real build.
        Throwable failure = new IllegalStateException("Failed to collect dependencies",
                new RuntimeException("resolution failed",
                        new IOException(REAL_MESSAGE)));

        QuarantineDetector.Verdict verdict = QuarantineDetector.inspect(failure);

        assertTrue(verdict.quarantined());
        assertTrue(verdict.forbidden());
        assertEquals("https://iq.nexus.privatbank.ua/ui/links/firewall/repositories/"
                + "quarantinedComponent/MzdhODY4NGRiODE4NDE0YTkwMmU0ZmIwMDA5ZjI0Njk",
                verdict.quarantineUrl());
    }

    @Test
    @DisplayName("a plain 403 is not a quarantine")
    void plainForbiddenIsNotQuarantine() {
        // Credentials being wrong means no version will work; treating it as a quarantine would
        // send the tool hunting through the whole version list for nothing.
        Throwable failure = new IOException(
                "Could not transfer artifact com.example:lib:jar:1.0 from/to nexus "
                        + "(https://nexus.example.com/): status code: 403, reason phrase: Forbidden");

        QuarantineDetector.Verdict verdict = QuarantineDetector.inspect(failure);

        assertFalse(verdict.quarantined());
        assertTrue(verdict.forbidden());
        assertNull(verdict.quarantineUrl());
    }

    @Test
    @DisplayName("an ordinary missing artifact is neither")
    void missingArtifact() {
        QuarantineDetector.Verdict verdict = QuarantineDetector.inspect(
                new IOException("The following artifacts could not be resolved: "
                        + "com.example:lib:jar:9.9.9 (absent)"));

        assertFalse(verdict.quarantined());
        assertFalse(verdict.forbidden());
    }

    @Test
    void toleratesNullsAndCycles() {
        assertFalse(QuarantineDetector.isQuarantined(new IllegalStateException((String) null)));

        RuntimeException cyclic = new RuntimeException("boom");
        cyclic.initCause(new RuntimeException("inner", cyclic));
        assertFalse(QuarantineDetector.isQuarantined(cyclic));
    }

    @Test
    @DisplayName("detects quarantine regardless of message casing")
    void caseInsensitive() {
        assertTrue(QuarantineDetector.isQuarantined(
                new IOException("status code: 403 - requested item is Quarantined")));
    }
}
