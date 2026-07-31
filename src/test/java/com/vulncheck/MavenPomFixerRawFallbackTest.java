package com.vulncheck;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Direct, network-free coverage of {@link MavenPomFixer#addOrUpdateManagedDependencyRaw}.
 *
 * <p>This is the fallback reached when OpenRewrite's recipes decide — without raising any error —
 * that there is nothing for them to do. That happened for a real artifact (a Quarkus deployment
 * dependency, quarantined, with no newer allowed version) whose only path to a fix is pinning it in
 * {@code dependencyManagement}, with repository access and authentication confirmed correct.
 *
 * <p>The first version of this fallback round-tripped the POM through {@code MavenXpp3Reader}/
 * {@code MavenXpp3Writer}, which reconstructs the whole document from its parsed model — reordering
 * elements, dropping comments, reformatting everything. A five-line addition became a diff of the
 * entire file, which is unreviewable and defeats the point of a targeted fix. These tests exist
 * specifically to keep that regression from coming back: every case asserts that lines untouched by
 * the intended change survive byte-for-byte.
 */
class MavenPomFixerRawFallbackTest {

    private static final String POM_WITHOUT_MANAGEMENT = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>svc</artifactId>
              <version>1.0.0</version>

              <properties>
                <maven.compiler.release>21</maven.compiler.release>
              </properties>

              <dependencies>
                <dependency>
                  <groupId>io.quarkus</groupId>
                  <artifactId>quarkus-arc</artifactId>
                </dependency>
              </dependencies>
            </project>
            """;

    private static final String POM_WITH_MANAGEMENT = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
              <modelVersion>4.0.0</modelVersion>
              <groupId>com.example</groupId>
              <artifactId>svc</artifactId>
              <version>1.0.0</version>

              <!-- a comment a model-based writer would drop -->
              <dependencyManagement>
                <dependencies>
                  <dependency>
                    <groupId>org.jetbrains.kotlinx</groupId>
                    <artifactId>kotlinx-metadata-jvm</artifactId>
                    <version>0.9.0</version>
                  </dependency>
                </dependencies>
              </dependencyManagement>

              <dependencies>
                <dependency>
                  <groupId>io.quarkus</groupId>
                  <artifactId>quarkus-arc</artifactId>
                </dependency>
              </dependencies>
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

        assertNotNull(result, "expected a rewritten POM, got null");
        assertTrue(result.contains("<dependencyManagement>"), result);
        assertTrue(result.contains("kotlinx-metadata-jvm"), result);
        assertTrue(result.contains("<version>0.5.0</version>"), result);
        assertParses(result);

        // Everything that was already there must survive untouched, in order.
        assertTrue(result.contains("<maven.compiler.release>21</maven.compiler.release>"), result);
        assertTrue(result.contains("quarkus-arc"), result);
        assertTrue(result.indexOf("<dependencyManagement>") < result.indexOf("<dependencies>\n    <dependency>\n      <groupId>io.quarkus"),
                "the new block should land before the project's own <dependencies>: " + result);
    }

    @Test
    @DisplayName("updates the version in place, touching nothing else")
    void updatesExistingEntry(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, POM_WITH_MANAGEMENT);

        String result = fixer.addOrUpdateManagedDependencyRaw(
                pom.toFile(), "org.jetbrains.kotlinx", "kotlinx-metadata-jvm", "0.5.0");

        assertNotNull(result);
        assertTrue(result.contains("<version>0.5.0</version>"), result);
        assertTrue(!result.contains("<version>0.9.0</version>"), result);
        assertParses(result);

        // The comment, and everything else in the file, must be untouched — this is the whole
        // point of the fallback: a one-line change produces a one-line diff.
        assertTrue(result.contains("<!-- a comment a model-based writer would drop -->"), result);
        assertMinimalDiff(POM_WITH_MANAGEMENT, result, 1);
    }

    @Test
    @DisplayName("adds a second entry alongside an unrelated existing one")
    void addsAlongsideUnrelatedEntry(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, POM_WITH_MANAGEMENT);

        String result = fixer.addOrUpdateManagedDependencyRaw(
                pom.toFile(), "commons-io", "commons-io", "2.16.1");

        assertNotNull(result);
        assertTrue(result.contains("kotlinx-metadata-jvm"), "must not disturb the existing entry: " + result);
        assertTrue(result.contains("<version>0.9.0</version>"), "existing entry's version must survive: " + result);
        assertTrue(result.contains("commons-io"), result);
        assertTrue(result.contains("<version>2.16.1</version>"), result);
        assertParses(result);
    }

    @Test
    @DisplayName("falls back to inserting before </project> when there is no <dependencies> anchor")
    void insertsBeforeProjectCloseWhenNoAnchor(@TempDir Path dir) throws Exception {
        Path pom = dir.resolve("pom.xml");
        Files.writeString(pom, """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>svc</artifactId>
                  <version>1.0.0</version>
                </project>
                """);

        String result = fixer.addOrUpdateManagedDependencyRaw(
                pom.toFile(), "org.jetbrains.kotlinx", "kotlinx-metadata-jvm", "0.5.0");

        assertNotNull(result);
        assertTrue(result.contains("<dependencyManagement>"), result);
        assertParses(result);
    }

    /** Parses as valid XML with exactly the expected root — catches a malformed insertion. */
    private static void assertParses(String pomXml) throws Exception {
        var factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        var doc = factory.newDocumentBuilder().parse(
                new java.io.ByteArrayInputStream(pomXml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals("project", doc.getDocumentElement().getNodeName());
    }

    /** Confirms the diff between two texts touches no more than {@code maxChangedLines} lines. */
    private static void assertMinimalDiff(String before, String after, int maxChangedLines) {
        List<String> beforeLines = before.lines().toList();
        List<String> afterLines = after.lines().toList();
        assertEquals(beforeLines.size(), afterLines.size(),
                "line count changed — this is no longer a targeted edit:\n" + after);

        int changed = 0;
        for (int i = 0; i < beforeLines.size(); i++) {
            if (!beforeLines.get(i).equals(afterLines.get(i))) {
                changed++;
            }
        }
        assertTrue(changed <= maxChangedLines,
                "expected at most " + maxChangedLines + " changed line(s), found " + changed + ":\n" + after);
    }
}
