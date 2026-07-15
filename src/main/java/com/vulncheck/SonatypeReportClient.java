package com.vulncheck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    public SonatypeReportClient(
            SonatypeCredentials sonatypeCredentials
    ) {
        Objects.requireNonNull(sonatypeCredentials, "sonatypeCredentials");

        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();

        String credentials = sonatypeCredentials.sonatypeUsername() + ":" + sonatypeCredentials.sonatypePassword();

        this.authorizationHeader = "Basic " + Base64.getEncoder()
                .encodeToString(
                        credentials.getBytes(StandardCharsets.UTF_8)
                );
    }

    public JsonNode fetchReportData(String reportDataUrl) {
        Objects.requireNonNull(reportDataUrl, "reportDataUrl");

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(reportDataUrl))
                .header("Accept", "application/json")
                .header("Authorization", authorizationHeader)
                .GET()
                .build();

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
                    "Cannot retrieve Sonatype report",
                    exception
            );
        }
    }
}
