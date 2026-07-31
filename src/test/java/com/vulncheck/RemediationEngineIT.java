package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end coverage of the remediation loop against real artifacts from Maven Central.
 *
 * <p>Uses CVE-2022-42889 ("Text4Shell") in {@code commons-text}, which is a stable, long-published
 * fact: 1.9 is affected, 1.10.0 is not. The point of these tests is that the engine only reports a
 * fix when the <em>resolved graph</em> actually changed — the property that the previous
 * implementation could not guarantee.
 */
@Tag("network")
class RemediationEngineIT {

    private static final String POM_TEMPLATE = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>subject</artifactId>
              <version>1.0.0</version>
              <dependencies>
            %s
              </dependencies>
            </project>
            """;

    private static String dependency(String groupId, String artifactId, String version) {
        return """
                    <dependency>
                      <groupId>%s</groupId>
                      <artifactId>%s</artifactId>
                      <version>%s</version>
                    </dependency>
                """.formatted(groupId, artifactId, version);
    }

    private static SonatypeScanReport reportFor(String groupId, String artifactId, String version, String... fixes) {
        var details = new SonatypeScanReport.VulnerabilityDetails(
                "pkg:maven/" + groupId + "/" + artifactId + "@" + version + "?type=jar",
                artifactId,
                List.of(new SonatypeScanReport.SecurityIssue("CVE-2022-42889", "9.8", "RCE", "cve", null)),
                false,
                List.of(),
                List.of(fixes).stream()
                        .map(v -> new SonatypeScanReport.RemediationVersion("next-no-violations", v, null))
                        .toList());
        return new SonatypeScanReport("test-app", "scan-1", null, 1, 1, List.of(details));
    }

    private ScanReport run(Path projectDir, SonatypeScanReport scan, RemediationEngine.Options options)
            throws Exception {
        TestRepositories.Wiring wiring = TestRepositories.requireReachableRepository();
        return new RemediationEngine(scan, wiring.system(), wiring.session(), wiring.repositories(),
                null, projectDir, options)
                .run(projectDir.resolve("pom.xml").toFile());
    }

    @Test
    @DisplayName("upgrades a directly declared vulnerable dependency and rewrites the POM")
    void fixesDirectDependency(@TempDir Path projectDir) throws Exception {
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, POM_TEMPLATE.formatted(
                dependency("org.apache.commons", "commons-text", "1.9")));

        ScanReport report = run(projectDir,
                reportFor("org.apache.commons", "commons-text", "1.9", "1.10.0"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12, false, false, false, null, null, 5));

        ScanReport.Finding finding = report.findings().getFirst();
        assertEquals(ScanReport.Outcome.FIXED, finding.outcome(), () -> finding.notes().toString());
        assertEquals("1.10.0", finding.toVersion());
        assertEquals(4, finding.severityRank(), "CVSS 9.8 must band to CRITICAL");

        String rewritten = Files.readString(pom);
        assertTrue(rewritten.contains("<version>1.10.0</version>"), rewritten);
        assertFalse(rewritten.contains("<version>1.9</version>"), rewritten);
    }

    @Test
    @DisplayName("--dry-run reports the same fix but leaves the POM untouched")
    void dryRunWritesNothing(@TempDir Path projectDir) throws Exception {
        Path pom = projectDir.resolve("pom.xml");
        String original = POM_TEMPLATE.formatted(
                dependency("org.apache.commons", "commons-text", "1.9"));
        Files.writeString(pom, original);

        ScanReport report = run(projectDir,
                reportFor("org.apache.commons", "commons-text", "1.9", "1.10.0"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, true, false, 12, false, false, false, null, null, 5));

        assertEquals(ScanReport.Outcome.WOULD_FIX, report.findings().getFirst().outcome());
        assertEquals(original, Files.readString(pom), "dry run must not modify the POM");
        assertFalse(report.anyChangesWritten());
    }

    @Test
    @DisplayName("reports a component that is not in the resolved graph rather than inventing a fix")
    void notInGraph(@TempDir Path projectDir) throws Exception {
        Files.writeString(projectDir.resolve("pom.xml"), POM_TEMPLATE.formatted(
                dependency("org.apache.commons", "commons-text", "1.10.0")));

        ScanReport report = run(projectDir,
                reportFor("com.example", "never-declared", "1.0", "2.0"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, true, false, 12, false, false, false, null, null, 5));

        assertEquals(ScanReport.Outcome.NOT_IN_GRAPH, report.findings().getFirst().outcome());
    }

    @Test
    @DisplayName("recognises a POM that is already on a fixed version")
    void alreadyFixed(@TempDir Path projectDir) throws Exception {
        Files.writeString(projectDir.resolve("pom.xml"), POM_TEMPLATE.formatted(
                dependency("org.apache.commons", "commons-text", "1.10.0")));

        ScanReport report = run(projectDir,
                reportFor("org.apache.commons", "commons-text", "1.9", "1.10.0"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, true, false, 12, false, false, false, null, null, 5));

        ScanReport.Finding finding = report.findings().getFirst();
        assertEquals(ScanReport.Outcome.NOT_AFFECTED, finding.outcome());
        assertEquals("1.10.0", finding.resolvedVersion());
    }

    @Test
    @DisplayName("fixes a transitive vulnerability by bumping the dependency that pulls it in")
    void fixesTransitiveViaDeclaredDependency(@TempDir Path projectDir) throws Exception {
        // commons-configuration2 2.7 depends on commons-text 1.8; later releases move to 1.10.0.
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, POM_TEMPLATE.formatted(
                dependency("org.apache.commons", "commons-configuration2", "2.7")));

        ScanReport report = run(projectDir,
                reportFor("org.apache.commons", "commons-text", "1.8", "1.10.0"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12, false, false, false, null, null, 5));

        ScanReport.Finding finding = report.findings().getFirst();
        assertEquals(ScanReport.Outcome.FIXED, finding.outcome(), () -> finding.notes().toString());
        assertFalse(finding.directDependency(), "commons-text is reached transitively");
        assertNotNull(finding.dependencyPath());
        assertTrue(finding.dependencyPath().contains("commons-configuration2"), finding.dependencyPath());

        // Whatever lever it used, the resolved graph must no longer contain an affected version.
        assertNoAffectedVersionRemains(projectDir, "org.apache.commons", "commons-text", "1.8",
                List.of("1.10.0"));
    }

    @Test
    @DisplayName("pins a transitive vulnerability in dependencyManagement when no bump can reach it")
    void fallsBackToManagedPin(@TempDir Path projectDir) throws Exception {
        // Every httpclient 4.5.x pins commons-codec 1.11, so within MINOR scope no upgrade of the
        // declared dependency can move it. The only lever left is a dependencyManagement pin.
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, POM_TEMPLATE.formatted(
                dependency("org.apache.httpcomponents", "httpclient", "4.5.13")));

        ScanReport report = run(projectDir,
                reportFor("commons-codec", "commons-codec", "1.11", "1.13"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12, false, false, false, null, null, 5));

        ScanReport.Finding finding = report.findings().getFirst();
        assertEquals(ScanReport.Outcome.FIXED, finding.outcome(), () -> finding.notes().toString());
        assertEquals("dependencyManagement pin", finding.controlPoint());

        String rewritten = Files.readString(pom);
        assertTrue(rewritten.contains("dependencyManagement"), rewritten);
        assertTrue(rewritten.contains("commons-codec"), rewritten);

        assertNoAffectedVersionRemains(projectDir, "commons-codec", "commons-codec", "1.11", List.of("1.13"));
    }

    @Test
    @DisplayName("reports honestly when the upgrade policy rules out every fix")
    void reportsWhenPolicyBlocksEveryFix(@TempDir Path projectDir) throws Exception {
        // PATCH scope keeps commons-text on the 1.8.x line, where no fixed version exists.
        Path pom = projectDir.resolve("pom.xml");
        String original = POM_TEMPLATE.formatted(
                dependency("org.apache.commons", "commons-configuration2", "2.7"));
        Files.writeString(pom, original);

        ScanReport report = run(projectDir,
                reportFor("org.apache.commons", "commons-text", "1.8", "1.10.0"),
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.PATCH, false, false, 12, false, false, false, null, null, 5));

        ScanReport.Finding finding = report.findings().getFirst();
        assertEquals(ScanReport.Outcome.NO_WORKING_FIX, finding.outcome());
        assertEquals(original, Files.readString(pom), "an unfixable finding must not alter the POM");
        assertTrue(report.outstanding().contains(finding));
        // The report has to say what to do about it, not just that it failed.
        assertTrue(finding.notes().stream().anyMatch(n -> n.contains("--upgrade-scope")), finding.notes().toString());
    }

    /** Independently re-resolves the project and asserts the vulnerability is genuinely gone. */
    private void assertNoAffectedVersionRemains(Path projectDir, String groupId, String artifactId,
                                                String vulnerableVersion, List<String> fixes) throws Exception {
        LocalProjectAnalyzer analyzer = TestRepositories.create().analyzer();

        File pom = projectDir.resolve("pom.xml").toFile();
        String resolved = analyzer.resolvedVersionOf(analyzer.buildGraphFromPom(pom), groupId, artifactId);

        assertTrue(resolved == null || !VersionPolicy.isStillAffected(resolved, vulnerableVersion, fixes),
                "graph still resolves an affected version: " + resolved);
    }
}
