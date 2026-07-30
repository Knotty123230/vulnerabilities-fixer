package com.vulncheck;

import org.eclipse.aether.graph.DependencyNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises the binary-compatibility check against real JARs.
 *
 * <p>The property that matters is the absence of false positives: a checker that flags healthy
 * upgrades gets disabled, and then it protects nobody.
 */
@Tag("network")
class LinkageAnalyzerIT {

    private LocalProjectAnalyzer analyzer() {
        var system = MavenResolverFactory.createRepositorySystem();
        var session = MavenResolverFactory.createSession(
                system, MavenResolverFactory.defaultLocalRepository(), null);
        return new LocalProjectAnalyzer(system, session, MavenResolverFactory.createRepositories(null));
    }

    @Test
    @DisplayName("an unchanged classpath yields no regressions")
    void unchangedClasspathIsClean(@TempDir Path projectDir) throws Exception {
        Files.createDirectories(projectDir.resolve("target/classes"));
        Files.writeString(projectDir.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>subject</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>org.apache.commons</groupId>
                <artifactId>commons-configuration2</artifactId><version>2.7</version></dependency></dependencies>
                </project>
                """);

        LocalProjectAnalyzer analyzer = analyzer();
        DependencyNode graph = analyzer.buildGraphFromPom(projectDir.resolve("pom.xml").toFile());

        LinkageAnalyzer linkage = new LinkageAnalyzer(analyzer, projectDir);
        linkage.establishBaseline(graph, "org.apache.commons", "commons-text");
        LinkageAnalyzer.Verdict verdict = linkage.verify(graph, "org.apache.commons", "commons-text");

        assertTrue(verdict.compatible(), () -> verdict.renderRegressions(10).toString());
        assertTrue(verdict.regressions().isEmpty(), () -> verdict.renderRegressions(10).toString());
    }

    @Test
    @DisplayName("a genuinely compatible upgrade is not flagged")
    void compatibleUpgradeIsAccepted(@TempDir Path projectDir) throws Exception {
        Files.createDirectories(projectDir.resolve("target/classes"));
        Path pom = projectDir.resolve("pom.xml");
        String template = """
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>subject</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>org.apache.commons</groupId>
                <artifactId>commons-configuration2</artifactId><version>%s</version></dependency></dependencies>
                </project>
                """;

        LocalProjectAnalyzer analyzer = analyzer();
        Files.writeString(pom, template.formatted("2.7"));
        DependencyNode before = analyzer.buildGraphFromPom(pom.toFile());

        LinkageAnalyzer linkage = new LinkageAnalyzer(analyzer, projectDir);
        linkage.establishBaseline(before, "org.apache.commons", "commons-text");

        analyzer.invalidate(pom.toFile());
        Files.writeString(pom, template.formatted("2.9.0"));
        DependencyNode after = analyzer.buildGraphFromPom(pom.toFile());

        LinkageAnalyzer.Verdict verdict = linkage.verify(after, "org.apache.commons", "commons-text");
        assertTrue(verdict.compatible(), () -> verdict.renderRegressions(10).toString());
    }

    @Test
    @DisplayName("skips gracefully, and does not veto a fix, when the project is not compiled")
    void skipsWhenNotCompiled(@TempDir Path projectDir) throws Exception {
        Files.writeString(projectDir.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>subject</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>org.apache.commons</groupId>
                <artifactId>commons-text</artifactId><version>1.10.0</version></dependency></dependencies>
                </project>
                """);

        LocalProjectAnalyzer analyzer = analyzer();
        DependencyNode graph = analyzer.buildGraphFromPom(projectDir.resolve("pom.xml").toFile());

        LinkageAnalyzer linkage = new LinkageAnalyzer(analyzer, projectDir);
        linkage.establishBaseline(graph, "org.apache.commons", "commons-text");
        LinkageAnalyzer.Verdict verdict = linkage.verify(graph, "org.apache.commons", "commons-text");

        assertTrue(verdict.wasSkipped());
        assertTrue(verdict.compatible(), "a check that could not run must not block a security fix");
        assertFalse(verdict.skipReason().isBlank());
    }
}
