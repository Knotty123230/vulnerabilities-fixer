package com.vulncheck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
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

    public JsonNode fetchReportData(String reportDataUrl) {
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

        JsonNode response = executeGet(url);
        JsonNode applications = response.get("applications");

        if (applications == null || applications.isEmpty()) {
            throw new IllegalStateException(
                    "No application found with publicId: " + publicApplicationId
            );
        }

        JsonNode idNode = applications.get(0).get("id");
        if (idNode == null) {
            throw new IllegalStateException(
                    "Application entry has no 'id' field for publicId: " + publicApplicationId
            );
        }

        return idNode.asText();
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
    public JsonNode fetchRemediation(
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

        ObjectNode body = objectMapper.createObjectNode();
        body.put("packageUrl", packageUrl);

        return executePost(url, body);
    }

    private JsonNode executeGet(String url) {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

        return executeRequest(request);
    }

    private JsonNode executePost(String url, JsonNode body) {
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

    private JsonNode executeRequest(HttpRequest request) {
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

            return objectMapper.readTree(response.body());

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
}
