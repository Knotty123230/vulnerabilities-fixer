package com.vulncheck;

import java.util.List;

public record SonatypeScanReport(
        String applicationId,
        String scanId,
        String reportUrl,
        int totalComponents,
        int vulnerableComponents,
        List<VulnerabilityDetails> vulnerabilities
) {
    public record VulnerabilityDetails(
            String packageUrl,
            String displayName,
            List<SecurityIssue> securityIssues,
            boolean directDependency,
            List<String> parentComponentPurls,
            List<RemediationVersion> remediationVersions
    ) {
    }

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
