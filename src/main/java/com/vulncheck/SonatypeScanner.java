package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class SonatypeScanner {


    private final SonatypeCredentials sonatypeCredentials;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SonatypeScanner(SonatypeCredentials sonatypeCredentials) {
        this.sonatypeCredentials = sonatypeCredentials;
    }


    public SonatypeScanResult scan(Path pathToProject) {
        if (!Files.isDirectory(pathToProject)) {
            throw new IllegalArgumentException("Path is not a directory");
        }

        List<String> commands = List.of(
                "mvn",
                "-B",
                "com.sonatype.clm:clm-maven-plugin:evaluate",
                "-Dclm.serverUrl=" + sonatypeCredentials.serverUrl(),
                "-Dclm.username=" + sonatypeCredentials.sonatypeUsername(),
                "-Dclm.password=" + sonatypeCredentials.sonatypePassword(),
                "-Dclm.applicationId=" + sonatypeCredentials.applicationId(),
                "-Dclm.stage=build",
                "-Dclm.resultsFile=target/clm-results.json"
        );


        ProcessBuilder processBuilder = new ProcessBuilder(commands);
        processBuilder.directory(pathToProject.toFile());
        processBuilder.redirectErrorStream(true);
        try {
            Process process = processBuilder.start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                throw new IllegalStateException("Sonatype scan failed with exit code " + exitCode + ". Output: " + output);
            }
            System.out.println(output);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot start Sonatype scan.", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Sonatype scan was interrupted.", exception);
        }

        SonatypeScanResult result;
        try {

            result = objectMapper.readValue(pathToProject.resolve("target/clm-results.json").toFile(), SonatypeScanResult.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return result;
    }


    public record SonatypeScanResult(
            String applicationId,
            String scanId,
            String reportHtmlUrl,
            String reportPdfUrl,
            String reportDataUrl
    ) {
    }


}
