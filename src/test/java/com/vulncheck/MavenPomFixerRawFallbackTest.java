package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Direct, network-free coverage of {@link MavenPomFixer#addOrUpdateManagedDependencyRaw}.
 *
 * <p>This is the fallback reached when OpenRewrite's recipes decide — without raising any error —
 * that there is nothing for them to do. That happened for a real artifact (a Quarkus deployment
 * dependency, quarantined, with no newer allowed version) whose only path to a fix is pinning it in
 * {@code dependencyManagement}: repository access and authentication were confirmed correct via the
 * "POM edits via" diagnostic, and no exception or recipe-reported error ever appeared, yet
 * {@code UpgradeDependencyVersion}, {@code ChangeDependencyGroupIdAndArtifactId} and
 * {@code AddManagedDependency} all produced no diff. Because that failure mode gives no signal to
 * assert on, this test exercises the raw fallback directly and does not depend on reproducing
 * OpenRewrite's internal decision.
 */
class MavenPomFixerRawFallbackTest {

    private static final String POM_WITHOUT_MANAGEMENT = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>svc</artifactId>
              <version>1.0.0</version>
            </project>
            """;

    private static final String POM_WITH_MANAGEMENT = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>svc</artifactId>
              <version>1.0.0</version>
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.jetbrains.kotlinx</groupId>
                    <artifactId>kotlinx-metadata-jvm</artifactId>
                    <version>0.9.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>
            </project>
            """;

    private final MavenPomFixer fixer = new MavenPomFixer(null);

    @Test
    @DisplayName("creates dependencyManagement and adds the entry when neither exists")
    void createsManagementSection(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, POM_WITHOUT_MANAGEMENT);

        String result = fixer.addOrUpdateManagedDependencyRaw(
                pom.toFile(), "org.jetbrains.kotlinx", "kotlinx-metadata-jvm", "0.5.0");

        assertTrue(result != null, "expected a rewritten POM, got null");
        assertTrue(result.contains("<dependencyManagement>"), result);
        assertTrue(result.contains("kotlinx-metadata-jvm"), result);
        assertTrue(result.contains("<version>0.5.0</version>"), result);
    }

    @Test
    @DisplayName("updates the version when the artifact is already managed")
    void updatesExistingEntry(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, POM_WITH_MANAGEMENT);

        String result = fixer.addOrUpdateManagedDependencyRaw(
                pom.toFile(), "org.jetbrains.kotlinx", "kotlinx-metadata-jvm", "0.5.0");

        assertTrue(result != null, "expected a rewritten POM, got null");
        assertTrue(result.contains("<version>0.5.0</version>"), result);
        assertTrue(!result.contains("<version>0.9.0</version>"), result);
        // Exactly one managed entry — this must edit in place, not add a duplicate alongside it.
        long occurrences = result.split("kotlinx-metadata-jvm", -1).length - 1;
        assertTrue(occurrences == 1, "expected exactly one entry, found " + occurrences + " in:\n" + result);
    }

    @Test
    @DisplayName("adds a second entry alongside an unrelated existing one")
    void addsAlongsideUnrelatedEntry(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, POM_WITH_MANAGEMENT);

        String result = fixer.addOrUpdateManagedDependencyRaw(
                pom.toFile(), "commons-io", "commons-io", "2.16.1");

        assertTrue(result.contains("kotlinx-metadata-jvm"), "must not disturb the existing entry: " + result);
        assertTrue(result.contains("commons-io"), result);
        assertTrue(result.contains("<version>2.16.1</version>"), result);
    }
}
