package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class PackageUrlParsingTest {

    private static SonatypeScanReport.VulnerabilityDetails details(String packageUrl, String... fixes) {
        return new SonatypeScanReport.VulnerabilityDetails(
                packageUrl, "display", List.of(), false, List.of(),
                List.of(fixes).stream()
                        .map(v -> new SonatypeScanReport.RemediationVersion("next-no-violations", v, null))
                        .toList());
    }

    @Test
    void parsesAPlainMavenPurl() {
        Vulnerability v = RemediationEngine.parsePackageUrl(
                details("pkg:maven/ch.qos.logback/logback-core@1.4.11"));

        assertEquals("ch.qos.logback", v.groupId());
        assertEquals("logback-core", v.artifactId());
        assertEquals("1.4.11", v.version());
    }

    @Test
    @DisplayName("strips purl qualifiers, which Sonatype always attaches")
    void stripsQualifiers() {
        Vulnerability v = RemediationEngine.parsePackageUrl(
                details("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0?type=jar"));

        assertEquals("com.fasterxml.jackson.core", v.groupId());
        assertEquals("jackson-databind", v.artifactId());
        assertEquals("2.13.0", v.version());
    }

    @Test
    void returnsRemediationVersionsAscending() {
        Vulnerability v = RemediationEngine.parsePackageUrl(
                details("pkg:maven/g/a@1.0", "1.10.0", "1.2.0", "1.9.0"));

        assertEquals(List.of("1.2.0", "1.9.0", "1.10.0"), v.versionToFix());
    }

    @Test
    @DisplayName("returns null for coordinates it cannot parse instead of throwing")
    void toleratesJunk() {
        // A single malformed entry must not abort a scan of everything else.
        assertNull(RemediationEngine.parsePackageUrl(details("pkg:npm/lodash@4.17.20")));
        assertNull(RemediationEngine.parsePackageUrl(details("pkg:maven/no-version-here")));
        assertNull(RemediationEngine.parsePackageUrl(details(null)));
    }
}
