package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Parsing is verified against real Maven output, copied verbatim from a failing Quarkus build.
 * The artifact in it — {@code kotlinx-metadata-jvm} — never appears in the project's dependency
 * graph, which is the whole reason this path exists.
 */
class BuildLogQuarantineScannerTest {

    private static final String REAL_BUILD_LOG = """
            [INFO] --- quarkus:3.32.3:generate-code (default) @ aismefinparse ---
            Downloading from nexus: https://nexus.privatbank.ua/repository/maven-public/org/jetbrains/kotlinx/kotlinx-metadata-jvm/0.9.0/kotlinx-metadata-jvm-0.9.0.jar
            [ERROR] [io.quarkus.bootstrap.resolver.maven.FailAtCompletionErrorHandler] 1)
            java.lang.RuntimeException: io.quarkus.bootstrap.resolver.maven.BootstrapMavenException: Failed to resolve artifact org.jetbrains.kotlinx:kotlinx-metadata-jvm:jar:0.9.0
                at io.quarkus.bootstrap.resolver.maven.ApplicationDependencyResolver$AppDep.initResolvedDependency (ApplicationDependencyResolver.java:621)
            Caused by: org.eclipse.aether.resolution.ArtifactResolutionException: The following artifacts could not be resolved: org.jetbrains.kotlinx:kotlinx-metadata-jvm:jar:0.9.0 (absent): Could not transfer artifact org.jetbrains.kotlinx:kotlinx-metadata-jvm:jar:0.9.0 from/to nexus (https://nexus.privatbank.ua/repository/maven-public/): status code: 403, reason phrase: -------------------->>> REQUESTED ITEM IS QUARANTINED -------------------->>> FOR DETAILS SEE ------>>> https://iq.nexus.privatbank.ua/ui/links/firewall/repositories/quarantinedComponent/YWU1MWQ1NWE4MjQ1NDMzOTg0MmMzZDZiYjNmY2MyYjQ <<<------ (403)
                at org.eclipse.aether.internal.impl.DefaultArtifactResolver.resolve (DefaultArtifactResolver.java:473)
            [INFO] BUILD FAILURE
            """;

    @Test
    @DisplayName("finds the quarantined artifact in real Quarkus build output")
    void parsesRealLog() {
        List<BuildLogQuarantineScanner.Hit> hits = BuildLogQuarantineScanner.scan(REAL_BUILD_LOG);

        assertEquals(1, hits.size(), hits.toString());
        BuildLogQuarantineScanner.Hit hit = hits.getFirst();

        assertEquals("org.jetbrains.kotlinx", hit.artifact().getGroupId());
        assertEquals("kotlinx-metadata-jvm", hit.artifact().getArtifactId());
        assertEquals("0.9.0", hit.artifact().getVersion());
        assertEquals("jar", hit.artifact().getExtension());
        assertEquals("https://iq.nexus.privatbank.ua/ui/links/firewall/repositories/"
                + "quarantinedComponent/YWU1MWQ1NWE4MjQ1NDMzOTg0MmMzZDZiYjNmY2MyYjQ",
                hit.quarantineUrl());
    }

    @Test
    @DisplayName("ignores coordinates on lines that are not about a quarantine")
    void ignoresUnrelatedCoordinates() {
        // Aether repeats a failure through many frames and mentions unrelated artifacts along
        // the way; collecting every coordinate in the log would produce mostly noise.
        String log = """
                [INFO] Building jar: /work/target/app.jar
                Downloading from nexus: .../com/example/other/1.0/other-1.0.jar
                [ERROR] Could not transfer artifact com.example:blocked:jar:2.0 from/to nexus: \
                status code: 403, reason phrase: REQUESTED ITEM IS QUARANTINED
                [ERROR] Failed to execute goal on project app: artifact com.example:unrelated:jar:3.0
                """;

        List<BuildLogQuarantineScanner.Hit> hits = BuildLogQuarantineScanner.scan(log);

        assertEquals(1, hits.size(), hits.toString());
        assertEquals("com.example:blocked:2.0", hits.getFirst().gav());
    }

    @Test
    @DisplayName("a plain 403 is not treated as a quarantine")
    void plainForbiddenIsIgnored() {
        String log = "[ERROR] Could not transfer artifact com.example:lib:jar:1.0 from/to nexus: "
                + "status code: 403, reason phrase: Forbidden";

        assertTrue(BuildLogQuarantineScanner.scan(log).isEmpty());
    }

    @Test
    void deduplicatesRepeatedReports() {
        // The same failure is echoed through several nested causes in every real log.
        String line = "Could not transfer artifact g:a:jar:1.0 from/to nexus: 403 QUARANTINED";
        assertEquals(1, BuildLogQuarantineScanner.scan(line + "\n" + line + "\n" + line).size());
    }

    @Test
    void handlesClassifiedArtifacts() {
        String log = "Could not transfer artifact io.netty:netty-transport-native-epoll:jar:"
                + "linux-x86_64:4.1.100.Final from/to nexus: 403 QUARANTINED";

        List<BuildLogQuarantineScanner.Hit> hits = BuildLogQuarantineScanner.scan(log);

        assertEquals(1, hits.size());
        assertEquals("4.1.100.Final", hits.getFirst().artifact().getVersion());
        assertEquals("linux-x86_64", hits.getFirst().artifact().getClassifier());
    }

    @Test
    void toleratesEmptyInput() {
        assertTrue(BuildLogQuarantineScanner.scan(null).isEmpty());
        assertTrue(BuildLogQuarantineScanner.scan("").isEmpty());
        assertTrue(BuildLogQuarantineScanner.scan("[INFO] BUILD SUCCESS").isEmpty());
    }
}
