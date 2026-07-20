package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class SonatypeReportClient {

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String authorizationHeader;
    private final String serverBaseUrl;

    public SonatypeReportClient(
            SonatypeCredentials sonatypeCredentials
    ) {
        Objects.requireNonNull(sonatypeCredentials, "sonatypeCredentials");

        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.objectMapper = new ObjectMapper();

        String rawUrl = sonatypeCredentials.serverUrl();
        this.serverBaseUrl = rawUrl.endsWith("/")
                ? rawUrl.substring(0, rawUrl.length() - 1)
                : rawUrl;

        String credentials = sonatypeCredentials.sonatypeUsername() + ":" + sonatypeCredentials.sonatypePassword();

        this.authorizationHeader = "Basic " + Base64.getEncoder()
                .encodeToString(
                        credentials.getBytes(StandardCharsets.UTF_8)
                );
    }

    public String fetchReportData(String reportDataUrl) {
        Objects.requireNonNull(reportDataUrl, "reportDataUrl");
        return executeGet(reportDataUrl);
    }

    /**
     * Resolves the internal application ID from the public application ID.
     * Calls GET /api/v2/applications?publicId={publicId}
     *
     * @return the internal application ID (UUID)
     */
    public String resolveApplicationInternalId(String publicApplicationId) {
        Objects.requireNonNull(publicApplicationId, "publicApplicationId");

        String url = serverBaseUrl
                + "/api/v2/applications?publicId="
                + publicApplicationId;

        ApplicationsResponse response;
        try {
            response = objectMapper.readValue(executeGet(url), ApplicationsResponse.class);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot deserialize Sonatype applications response", exception);
        }
        List<SonatypeApplication> applications = response.applications();

        if (applications.isEmpty()) {
            throw new IllegalStateException(
                    "No application found with publicId: " + publicApplicationId
            );
        }

        String applicationId = applications.getFirst().id();
        if (applicationId == null || applicationId.isBlank()) {
            throw new IllegalStateException(
                    "Application entry has no 'id' field for publicId: " + publicApplicationId
            );
        }

        return applicationId;
    }

    /**
     * Fetches remediation recommendations for a component.
     * Calls POST /api/v2/components/remediation/application/{applicationInternalId}?stageId=build&scanId={scanId}
     *
     * @param applicationInternalId the internal (UUID) application ID
     * @param packageUrl            the package URL of the component (e.g. pkg:maven/group/artifact@version?type=jar)
     * @param scanId                the scan ID from Sonatype scan result
     * @return the remediation JSON response
     */
    public String fetchRemediation(
            String applicationInternalId,
            String packageUrl,
            String scanId
    ) {
        Objects.requireNonNull(applicationInternalId, "applicationInternalId");
        Objects.requireNonNull(packageUrl, "packageUrl");
        Objects.requireNonNull(scanId, "scanId");

        String url = serverBaseUrl
                + "/api/v2/components/remediation/application/"
                + applicationInternalId
                + "?stageId=build&scanId=" + scanId;

        return executePost(url, Map.of("packageUrl", packageUrl));
    }

    private String executeGet(String url) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        return executeRequest(request);
    }

    private String executePost(String url, Object body) {
        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(body);
        } catch (IOException e) {
            throw new IllegalStateException("Cannot serialize request body", e);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Authorization", authorizationHeader)
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

        return executeRequest(request);
    }

    private String executeRequest(HttpRequest request) {
        try {
            HttpResponse<String> response = httpClient.send(
                    request,
                    HttpResponse.BodyHandlers.ofString()
            );

            if (response.statusCode() / 100 != 2) {
                throw new IllegalStateException(
                        "Sonatype returned HTTP "
                                + response.statusCode()
                                + ": "
                                + response.body()
                );
            }

            return response.body();

        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Sonatype request was interrupted",
                    exception
            );
        } catch (IOException exception) {
            throw new IllegalStateException(
                    "Cannot retrieve Sonatype data",
                    exception
            );
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ApplicationsResponse(List<SonatypeApplication> applications) {
        private ApplicationsResponse {
            applications = applications == null ? List.of() : List.copyOf(applications);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SonatypeApplication(String id) {
    }
}
