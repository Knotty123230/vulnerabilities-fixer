package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Version-skew detection and BOM-based alignment against real artifacts.
 *
 * <p>Netty is the canonical case: {@code netty-buffer} and {@code netty-common} at different
 * versions build fine and fail at runtime. Note that {@code netty-bom} has historically not
 * covered the {@code netty-transport-native-*} artifacts (netty/netty#6738), which is why
 * alignment is verified by re-resolving rather than by trusting the recipe.
 */
@Tag("network")
class VersionSkewIT {

    private static final String NETTY_SKEWED = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>subject</artifactId>
              <version>1.0.0</version>
              <dependencies>
                <dependency>
                  <groupId>io.netty</groupId>
                  <artifactId>netty-buffer</artifactId>
                  <version>4.1.100.Final</version>
                </dependency>
                <dependency>
                  <groupId>io.netty</groupId>
                  <artifactId>netty-codec</artifactId>
                  <version>4.1.110.Final</version>
                </dependency>
              </dependencies>
            </project>
            """;

    private VersionSkewDetector detector(TestRepositories.Wiring wiring) {
        VersionCatalog catalog = new VersionCatalog(wiring.system(), wiring.session(), wiring.repositories());
        return new VersionSkewDetector(
                new BomLocator(wiring.system(), wiring.session(), wiring.repositories(), catalog));
    }

    @Test
    @DisplayName("detects a Netty family split across two versions and names its BOM")
    void detectsNettySkew(@TempDir Path projectDir) throws Exception {
        Files.writeString(projectDir.resolve("pom.xml"), NETTY_SKEWED);

        TestRepositories.Wiring wiring = TestRepositories.requireReachableRepository();
        var graph = wiring.analyzer().buildGraphFromPom(projectDir.resolve("pom.xml").toFile());

        List<VersionSkewDetector.Skew> skews = detector(wiring).detect(graph);

        VersionSkewDetector.Skew netty = skews.stream()
                .filter(s -> s.groupId().equals("io.netty"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("expected io.netty skew, got " + skews));

        assertTrue(netty.distinctVersions().size() >= 2, netty.distinctVersions().toString());
        assertEquals("io.netty:netty-bom", netty.bomCoordinate());
    }

    @Test
    @DisplayName("does not flag a group whose artifacts are versioned independently")
    void ignoresIndependentlyVersionedGroup(@TempDir Path projectDir) throws Exception {
        // commons-lang3 3.x and commons-text 1.x share a groupId and are supposed to differ.
        // Grouping by groupId alone would report this as skew; requiring a lockstep BOM must not.
        Files.writeString(projectDir.resolve("pom.xml"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId><artifactId>subject</artifactId><version>1.0.0</version>
                  <dependencies>
                    <dependency><groupId>org.apache.commons</groupId>
                      <artifactId>commons-lang3</artifactId><version>3.12.0</version></dependency>
                    <dependency><groupId>org.apache.commons</groupId>
                      <artifactId>commons-text</artifactId><version>1.10.0</version></dependency>
                  </dependencies>
                </project>
                """);

        TestRepositories.Wiring wiring = TestRepositories.requireReachableRepository();
        var graph = wiring.analyzer().buildGraphFromPom(projectDir.resolve("pom.xml").toFile());

        assertTrue(detector(wiring).detect(graph).stream()
                        .noneMatch(s -> s.groupId().equals("org.apache.commons")),
                "org.apache.commons must not be treated as a lockstep family");
    }

    @Test
    @DisplayName("--align-families imports the BOM and puts the whole family on one version")
    void alignsNettyViaBomImport(@TempDir Path projectDir) throws Exception {
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, NETTY_SKEWED);

        var details = new SonatypeScanReport.VulnerabilityDetails(
                "pkg:maven/io.netty/netty-codec@4.1.110.Final?type=jar",
                "netty-codec",
                List.of(new SonatypeScanReport.SecurityIssue("CVE-2024-0000", "7.5", "dos", "cve", null)),
                true, List.of(),
                List.of(new SonatypeScanReport.RemediationVersion(
                        "next-no-violations", "4.1.118.Final", null)));
        var scan = new SonatypeScanReport("test-app", "scan-1", null, 2, 1, List.of(details));

        TestRepositories.Wiring wiring = TestRepositories.requireReachableRepository();
        ScanReport report = new RemediationEngine(scan, wiring.system(), wiring.session(),
                wiring.repositories(), null, projectDir,
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12, true, false, false, null, null, 5))
                .run(pom.toFile());

        ScanReport.Finding finding = report.findings().getFirst();
        assertEquals(ScanReport.Outcome.FIXED, finding.outcome(), () -> finding.notes().toString());
        assertEquals("family BOM import", finding.controlPoint(), () -> finding.appliedChange());

        String rewritten = Files.readString(pom);
        assertTrue(rewritten.contains("netty-bom"), rewritten);
        assertTrue(rewritten.contains("<scope>import</scope>"), rewritten);

        // The real test: re-resolve and confirm every Netty artifact now agrees on one version.
        var graph = TestRepositories.create().analyzer().buildGraphFromPom(pom.toFile());
        Set<String> nettyVersions = collectNettyVersions(graph);
        assertEquals(1, nettyVersions.size(), "netty family still skewed: " + nettyVersions);

        assertFalse(report.familySkews().stream().anyMatch(s -> s.groupId().equals("io.netty")),
                "skew must be gone from the final report");
    }

    private static Set<String> collectNettyVersions(org.eclipse.aether.graph.DependencyNode root) {
        Set<String> versions = new java.util.TreeSet<>();
        root.accept(new org.eclipse.aether.graph.DependencyVisitor() {
            @Override
            public boolean visitEnter(org.eclipse.aether.graph.DependencyNode node) {
                var artifact = node.getArtifact();
                if (artifact != null && "io.netty".equals(artifact.getGroupId())) {
                    versions.add(artifact.getVersion());
                }
                return true;
            }

            @Override
            public boolean visitLeave(org.eclipse.aether.graph.DependencyNode node) {
                return true;
            }
        });
        return versions;
    }

    @Test
    @DisplayName("--align-families fixes skew even when the scan reports no vulnerabilities")
    void alignsWithoutAnyVulnerability(@TempDir Path projectDir) throws Exception {
        // The common case in practice: a clean security report but a family that has drifted.
        // Alignment used to run only inside vulnerability remediation, so with zero findings the
        // flag silently did nothing while the report still advised using it.
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, NETTY_SKEWED);

        var emptyScan = new SonatypeScanReport("test-app", "scan-1", null, 5, 0, List.of());

        TestRepositories.Wiring wiring = TestRepositories.requireReachableRepository();
        ScanReport report = new RemediationEngine(emptyScan, wiring.system(), wiring.session(),
                wiring.repositories(), null, projectDir,
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12,
                        true, false, false, null, null, 5))
                .run(pom.toFile());

        assertTrue(report.findings().isEmpty(), "no vulnerabilities in this scenario");
        assertEquals(1, report.familySkews().size(), report.familySkews().toString());

        ScanReport.FamilySkew netty = report.familySkews().getFirst();
        assertTrue(netty.aligned(), () -> netty.notes().toString());
        assertNotNull(netty.appliedChange());
        assertTrue(netty.appliedChange().contains("netty-bom"), netty.appliedChange());

        String rewritten = Files.readString(pom);
        assertTrue(rewritten.contains("netty-bom"), rewritten);
        assertTrue(rewritten.contains("<scope>import</scope>"), rewritten);

        // The whole point: the family must actually converge, not merely gain a BOM entry.
        var graph = TestRepositories.create().analyzer().buildGraphFromPom(pom.toFile());
        assertEquals(1, collectNettyVersions(graph).size(),
                "netty family still skewed: " + collectNettyVersions(graph));
    }

    @Test
    @DisplayName("without the flag, skew is reported and the POM is left alone")
    void reportsSkewWithoutTouchingPom(@TempDir Path projectDir) throws Exception {
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, NETTY_SKEWED);

        var emptyScan = new SonatypeScanReport("test-app", "scan-1", null, 5, 0, List.of());

        TestRepositories.Wiring wiring = TestRepositories.requireReachableRepository();
        ScanReport report = new RemediationEngine(emptyScan, wiring.system(), wiring.session(),
                wiring.repositories(), null, projectDir,
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12,
                        false, false, false, null, null, 5))
                .run(pom.toFile());

        assertEquals(1, report.familySkews().size());
        assertFalse(report.familySkews().getFirst().aligned());
        assertEquals(NETTY_SKEWED, Files.readString(pom), "POM must be untouched without the flag");
    }

    @Test
    @DisplayName("BOM coordinate guessing follows naming convention and the curated table")
    void bomCandidateNaming() {
        assertTrue(BomLocator.candidateCoordinates("io.netty", Set.of("netty-codec", "netty-buffer"))
                .contains("io.netty:netty-bom"));
        assertTrue(BomLocator.candidateCoordinates("io.grpc", Set.of("grpc-core"))
                .contains("io.grpc:grpc-bom"));
        // Jackson's BOM lives under a different groupId than its artifacts — convention alone fails.
        assertTrue(BomLocator.candidateCoordinates("com.fasterxml.jackson.core", Set.of("jackson-databind"))
                .contains("com.fasterxml.jackson:jackson-bom"));
    }
}
