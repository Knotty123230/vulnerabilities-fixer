package com.vulncheck;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

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


    public void scan(Path pathToProject, String applicationId) {
        SonatypeScanner.SonatypeScanResult scanResult = sonatypeScanner.scan(pathToProject);

        String reportDataUrl = buildReportDataUrl(
                credentials.serverUrl(),
                applicationId,
                scanResult.scanId()
        );
        JsonNode reportData = sonatypeClient.fetchReportData(reportDataUrl);

        // Resolve internal application ID for remediation API
        String applicationInternalId = sonatypeClient.resolveApplicationInternalId(applicationId);

        // Find components with security issues and fetch remediation
        JsonNode components = reportData.get("components");
        List<VulnerableComponentResult> vulnerableComponents = new ArrayList<>();

        if (components != null && components.isArray()) {
            for (JsonNode component : components) {
                JsonNode securityData = component.get("securityData");
                if (securityData == null) continue;

                JsonNode securityIssues = securityData.get("securityIssues");
                if (securityIssues == null || securityIssues.isEmpty()) continue;

                String packageUrl = component.has("packageUrl")
                        ? component.get("packageUrl").asText()
                        : null;

                if (packageUrl == null || packageUrl.isBlank()) continue;

                JsonNode remediation = null;
                try {
                    remediation = sonatypeClient.fetchRemediation(
                            applicationInternalId,
                            packageUrl,
                            scanResult.scanId()
                    );
                } catch (Exception e) {
                    System.err.println("Warning: could not fetch remediation for "
                            + packageUrl + ": " + e.getMessage());
                }

                vulnerableComponents.add(new VulnerableComponentResult(
                        component,
                        remediation
                ));
            }
        }

        // Build output
        ObjectNode output = objectMapper.createObjectNode();
        output.put("applicationId", applicationId);
        output.put("scanId", scanResult.scanId());
        output.put("reportUrl", scanResult.reportHtmlUrl());
        output.put("totalComponents", components != null ? components.size() : 0);
        output.put("vulnerableComponents", vulnerableComponents.size());

        ArrayNode vulnerabilities = output.putArray("vulnerabilities");
        for (VulnerableComponentResult vcr : vulnerableComponents) {
            ObjectNode entry = objectMapper.createObjectNode();

            JsonNode comp = vcr.component();
            entry.put("packageUrl", comp.get("packageUrl").asText());
            entry.put("displayName", comp.has("displayName")
                    ? comp.get("displayName").asText() : "");

            // Copy security issues
            entry.set("securityIssues", comp.get("securityData").get("securityIssues"));

            // Dependency info
            JsonNode depData = comp.get("dependencyData");
            if (depData != null) {
                entry.put("directDependency", depData.has("directDependency")
                        && depData.get("directDependency").asBoolean());
                if (depData.has("parentComponentPurls")) {
                    entry.set("parentComponentPurls", depData.get("parentComponentPurls"));
                }
            }

            // Remediation - extract recommended fix versions
            if (vcr.remediation() != null) {
                JsonNode remediationNode = vcr.remediation().get("remediation");
                if (remediationNode != null && remediationNode.has("versionChanges")) {
                    ArrayNode fixVersions = objectMapper.createArrayNode();
                    for (JsonNode versionChange : remediationNode.get("versionChanges")) {
                        ObjectNode fix = objectMapper.createObjectNode();
                        fix.put("type", versionChange.has("type")
                                ? versionChange.get("type").asText() : "unknown");

                        JsonNode data = versionChange.get("data");
                        if (data != null && data.has("component")) {
                            JsonNode fixComp = data.get("component");
                            if (fixComp.has("componentIdentifier")) {
                                JsonNode coords = fixComp.get("componentIdentifier").get("coordinates");
                                if (coords != null && coords.has("version")) {
                                    fix.put("version", coords.get("version").asText());
                                }
                            }
                            if (fixComp.has("packageUrl")) {
                                fix.put("packageUrl", fixComp.get("packageUrl").asText());
                            }
                        }

                        fixVersions.add(fix);
                    }
                    entry.set("remediationVersions", fixVersions);
                }
            }

            vulnerabilities.add(entry);
        }

        try {
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(output));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }


    public static String buildReportDataUrl(
            String serverUrl,
            String applicationId,
            String scanId
    ) {
        String base = serverUrl.endsWith("/")
                ? serverUrl.substring(0, serverUrl.length() - 1)
                : serverUrl;

        return base
                + "/api/v2/applications/"
                + applicationId
                + "/reports/"
                + scanId;
    }

    private record VulnerableComponentResult(
            JsonNode component,
            JsonNode remediation
    ) {
    }
}
