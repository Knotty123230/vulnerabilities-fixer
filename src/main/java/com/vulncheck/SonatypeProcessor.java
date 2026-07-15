package com.vulncheck;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;

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
        JsonNode jsonNode = sonatypeClient.fetchReportData(buildReportDataUrl(
                credentials.serverUrl(),
                applicationId,
                scanResult.scanId()
        ));
        try {
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonNode));
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
}
