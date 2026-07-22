package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SonatypeScanner {

    private static final Pattern REPORT_URL_PATTERN = Pattern.compile(
            "The detailed report can be viewed at:\\s*(https?://\\S+)");

    private static final Pattern POLICY_ACTION_PATTERN = Pattern.compile(
            "Policy Action:\\s*(\\S+)");

    private final SonatypeCredentials sonatypeCredentials;

    public SonatypeScanner(SonatypeCredentials sonatypeCredentials) {
        this.sonatypeCredentials = Objects.requireNonNull(
                sonatypeCredentials,
                "sonatypeCredentials");
    }

    public SonatypeScanResult scan(Path pathToProject) {
        Objects.requireNonNull(pathToProject, "pathToProject");

        if (!Files.isDirectory(pathToProject)) {
            throw new IllegalArgumentException(
                    "Path is not a directory: " + pathToProject);
        }

        Path pomFile = pathToProject.resolve("pom.xml");

        if (!Files.isRegularFile(pomFile)) {
            throw new IllegalArgumentException(
                    "pom.xml not found: " + pomFile);
        }

        ProcessBuilder processBuilder = getProcessBuilder(pathToProject);

        final String output;
        final int exitCode;

        try {
            Process process = processBuilder.start();

            output = new String(
                    process.getInputStream().readAllBytes(),
                    StandardCharsets.UTF_8);

            exitCode = process.waitFor();

        } catch (IOException exception) {
            throw new IllegalStateException(
                    "Cannot start Sonatype scan",
                    exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            throw new IllegalStateException(
                    "Sonatype scan was interrupted",
                    exception);
        }

        String reportHtmlUrl = extractRequired(
                output);

        String policyAction = extractOptional(
                output);

        String scanId = extractScanId(reportHtmlUrl);

        ScanStatus status = determineStatus(
                exitCode,
                reportHtmlUrl,
                policyAction);

        return new SonatypeScanResult(
                sonatypeCredentials.applicationId(),
                scanId,
                reportHtmlUrl,
                policyAction,
                status,
                exitCode,
                output);
    }

    private ProcessBuilder getProcessBuilder(Path pathToProject) {
        List<String> command = List.of(
                "mvn",
                "-B",
                "com.sonatype.clm:clm-maven-plugin:3.0.10-01:evaluate",
                "-Dclm.serverUrl=" + sonatypeCredentials.serverUrl(),
                "-Dclm.username=" + sonatypeCredentials.sonatypeUsername(),
                "-Dclm.password=" + sonatypeCredentials.sonatypePassword(),
                "-Dclm.applicationId=" + sonatypeCredentials.applicationId(),
                "-Dclm.stage=build");

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(pathToProject.toFile());
        processBuilder.redirectErrorStream(true);
        return processBuilder;
    }

    private static String extractRequired(
            String output) {
        Matcher matcher = SonatypeScanner.REPORT_URL_PATTERN.matcher(output);

        if (!matcher.find()) {
            throw new IllegalStateException(
                    "Sonatype report URL was not found in Maven output"
                            + System.lineSeparator()
                            + "Maven output:"
                            + System.lineSeparator()
                            + output);
        }

        return matcher.group(1).trim();
    }

    private static String extractOptional(
            String output) {
        Matcher matcher = SonatypeScanner.POLICY_ACTION_PATTERN.matcher(output);

        return matcher.find()
                ? matcher.group(1).trim()
                : null;
    }

    private static String extractScanId(String reportUrl) {
        int reportIndex = reportUrl.lastIndexOf("/report/");

        if (reportIndex < 0) {
            throw new IllegalStateException(
                    "Cannot extract scan ID from report URL: " + reportUrl);
        }

        String scanId = reportUrl.substring(
                reportIndex + "/report/".length());

        int queryIndex = scanId.indexOf('?');

        if (queryIndex >= 0) {
            scanId = scanId.substring(0, queryIndex);
        }

        int fragmentIndex = scanId.indexOf('#');

        if (fragmentIndex >= 0) {
            scanId = scanId.substring(0, fragmentIndex);
        }

        if (scanId.isBlank()) {
            throw new IllegalStateException(
                    "Empty scan ID in report URL: " + reportUrl);
        }

        return scanId;
    }

    private static ScanStatus determineStatus(
            int exitCode,
            String reportUrl,
            String policyAction) {
        /*
         * Якщо report URL існує, evaluation завершилась.
         * Ненульовий exit code може означати policy failure.
         */
        if (reportUrl != null) {
            if ("fail".equalsIgnoreCase(policyAction)
                    || exitCode != 0) {
                return ScanStatus.POLICY_FAILED;
            }

            return ScanStatus.COMPLETED;
        }

        return ScanStatus.TECHNICAL_FAILURE;
    }

    public enum ScanStatus {
        COMPLETED,
        POLICY_FAILED,
        TECHNICAL_FAILURE
    }

    public record SonatypeScanResult(
            String applicationId,
            String scanId,
            String reportHtmlUrl,
            String policyAction,
            ScanStatus status,
            int exitCode,
            String rawOutput) {
    }
}
