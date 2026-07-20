package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class SonatypeProcessor {
    private final SonatypeReportClient sonatypeClient;
    private final SonatypeScanner sonatypeScanner;
    private final ObjectMapper objectMapper;
    private final SonatypeCredentials credentials;

    public SonatypeProcessor(SonatypeCredentialsStore credentialsStore) {
        this(credentialsStore.getCredentials());
    }

    public SonatypeProcessor(SonatypeCredentials credentials) {
        this.sonatypeClient = new SonatypeReportClient(credentials);
        this.sonatypeScanner = new SonatypeScanner(credentials);
        this.objectMapper = new ObjectMapper();
        this.credentials = credentials;
    }

    public SonatypeScanReport scan(Path pathToProject, String applicationId) {
        SonatypeScanner.SonatypeScanResult scanResult = sonatypeScanner.scan(pathToProject);
        SonatypeReportData reportData = readValue(
                sonatypeClient.fetchReportData(buildReportDataUrl(
                        credentials.serverUrl(), applicationId, scanResult.scanId())),
                SonatypeReportData.class
        );
        String applicationInternalId = sonatypeClient.resolveApplicationInternalId(applicationId);
        List<SonatypeScanReport.VulnerabilityDetails> vulnerabilities = new ArrayList<>();

        for (ReportComponent component : reportData.components()) {
            if (!component.hasSecurityIssues() || component.packageUrl() == null || component.packageUrl().isBlank()) {
                continue;
            }

            RemediationResponse remediation = fetchRemediation(
                    applicationInternalId, component.packageUrl(), scanResult.scanId());
            vulnerabilities.add(toVulnerabilityDetails(component, remediation));
        }

        return new SonatypeScanReport(
                applicationId,
                scanResult.scanId(),
                scanResult.reportHtmlUrl(),
                reportData.components().size(),
                vulnerabilities.size(),
                List.copyOf(vulnerabilities)
        );
    }

    private RemediationResponse fetchRemediation(String applicationInternalId, String packageUrl, String scanId) {
        try {
            return readValue(
                    sonatypeClient.fetchRemediation(applicationInternalId, packageUrl, scanId),
                    RemediationResponse.class
            );
        } catch (RuntimeException exception) {
            return RemediationResponse.EMPTY;
        }
    }

    private SonatypeScanReport.VulnerabilityDetails toVulnerabilityDetails(
            ReportComponent component,
            RemediationResponse remediation
    ) {
        DependencyData dependencyData = component.dependencyData();
        return new SonatypeScanReport.VulnerabilityDetails(
                component.packageUrl(),
                Objects.requireNonNullElse(component.displayName(), ""),
                component.securityData().securityIssues(),
                dependencyData != null && dependencyData.directDependency(),
                dependencyData == null ? List.of() : dependencyData.parentComponentPurls(),
                remediation.remediation().versionChanges().stream()
                        .map(this::toRemediationVersion)
                        .toList()
        );
    }

    private SonatypeScanReport.RemediationVersion toRemediationVersion(VersionChange versionChange) {
        RemediationComponent component = versionChange.data() == null ? null : versionChange.data().component();
        ComponentIdentifier identifier = component == null ? null : component.componentIdentifier();
        Coordinates coordinates = identifier == null ? null : identifier.coordinates();
        return new SonatypeScanReport.RemediationVersion(
                Objects.requireNonNullElse(versionChange.type(), "unknown"),
                coordinates == null ? null : coordinates.version(),
                component == null ? null : component.packageUrl()
        );
    }

    private <T> T readValue(String json, Class<T> targetType) {
        try {
            return objectMapper.readValue(json, targetType);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot deserialize Sonatype response", exception);
        }
    }

    public static String buildReportDataUrl(String serverUrl, String applicationId, String scanId) {
        String base = serverUrl.endsWith("/")
                ? serverUrl.substring(0, serverUrl.length() - 1)
                : serverUrl;
        return base + "/api/v2/applications/" + applicationId + "/reports/" + scanId;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SonatypeReportData(List<ReportComponent> components) {
        private SonatypeReportData {
            components = components == null ? List.of() : List.copyOf(components);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ReportComponent(String packageUrl, String displayName, SecurityData securityData,
                                   DependencyData dependencyData) {
        private boolean hasSecurityIssues() {
            return securityData != null && !securityData.securityIssues().isEmpty();
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SecurityData(List<SonatypeScanReport.SecurityIssue> securityIssues) {
        private SecurityData {
            securityIssues = securityIssues == null ? List.of() : List.copyOf(securityIssues);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record DependencyData(boolean directDependency, List<String> parentComponentPurls) {
        private DependencyData {
            parentComponentPurls = parentComponentPurls == null ? List.of() : List.copyOf(parentComponentPurls);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record RemediationResponse(Remediation remediation) {
        private static final RemediationResponse EMPTY = new RemediationResponse(Remediation.EMPTY);

        private RemediationResponse {
            remediation = remediation == null ? Remediation.EMPTY : remediation;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Remediation(List<VersionChange> versionChanges) {
        private static final Remediation EMPTY = new Remediation(List.of());

        private Remediation {
            versionChanges = versionChanges == null ? List.of() : List.copyOf(versionChanges);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record VersionChange(String type, VersionChangeData data) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record VersionChangeData(RemediationComponent component) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record RemediationComponent(ComponentIdentifier componentIdentifier, String packageUrl) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ComponentIdentifier(Coordinates coordinates) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Coordinates(String version) {
    }
}
