package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

public record SonatypeScanReport(
        String applicationId,
        String scanId,
        String reportUrl,
        int totalComponents,
        int vulnerableComponents,
        List<VulnerabilityDetails> vulnerabilities
) {

    /**
     * An empty report, for runs that analyse the dependency graph without a vulnerability scan
     * ({@code --fix-quarantined}, {@code --align-families}).
     */
    public static SonatypeScanReport none() {
        return new SonatypeScanReport(null, null, null, 0, 0, List.of());
    }
    public record VulnerabilityDetails(
            String packageUrl,
            String displayName,
            List<SecurityIssue> securityIssues,
            boolean directDependency,
            List<String> parentComponentPurls,
            List<RemediationVersion> remediationVersions
    ) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record SecurityIssue(
            String reference,
            String severity,
            String reason,
            String source,
            String url
    ) {
    }

    public record RemediationVersion(
            String type,
            String version,
            String packageUrl
    ) {
    }
}
