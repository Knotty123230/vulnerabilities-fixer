package com.vulncheck;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Path;

public class SonatypeProcessor {
    private final SonatypeReportClient sonatypeClient;
    private final SonatypeScanner sonatypeScanner;
    private final ObjectMapper objectMapper;

    public SonatypeProcessor(SonatypeCredentialsStore credentialsStore) {
        this(credentialsStore.getCredentials());
    }

    public SonatypeProcessor(SonatypeCredentials credentials) {
        this.sonatypeClient = new SonatypeReportClient(credentials);
        this.sonatypeScanner = new SonatypeScanner(credentials);
        this.objectMapper = new ObjectMapper();
    }


    public void scan(Path pathToProject) {
        SonatypeScanner.SonatypeScanResult scanResult = sonatypeScanner.scan(pathToProject);
        JsonNode jsonNode = sonatypeClient.fetchReportData(scanResult.reportDataUrl());
        try {
            System.out.println(objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(jsonNode));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

    }
}
