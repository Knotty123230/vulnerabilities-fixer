package com.vulncheck;

import com.sun.net.httpserver.HttpServer;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the Sonatype Repository Firewall path end to end against a stub proxy that quarantines
 * one specific version and passes everything else through to Maven Central.
 *
 * <p>Worth stubbing rather than mocking: the behaviour under test is how a real 403 surfaces
 * through Maven Resolver, and that turned out to be transport-dependent — resolver 2.x reports
 * only {@code HTTP Status: 403} and discards the body that names the quarantine, so a unit test
 * over a hand-built exception would have happily passed while the tool misread every real refusal
 * as "version not found".
 */
@Tag("network")
class QuarantineRemediationIT {

    private static final String QUARANTINED_PATH =
            "/org/apache/commons/commons-text/1.10.0/commons-text-1.10.0.jar";
    private static final String QUARANTINE_BODY =
            "-------------------->>> REQUESTED ITEM IS QUARANTINED -------------------->>> "
                    + "FOR DETAILS SEE ------>>> https://iq.example.com/ui/links/firewall/"
                    + "repositories/quarantinedComponent/ABCD1234EFGH5678 <<<------";

    /** Shared so the proxy does not build a new connection pool per request. */
    private static final HttpClient UPSTREAM = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .build();

    /**
     * One local repository for the whole class. A per-test repository forced every POM and JAR to
     * be fetched again through the stub, which dominated the runtime; the quarantined artifact is
     * never cached because it never downloads, so sharing does not weaken the test.
     */
    @TempDir(cleanup = org.junit.jupiter.api.io.CleanupMode.ALWAYS)
    static Path sharedLocalRepository;

    /** When set, every version of this artifact path prefix is refused. */
    private volatile String quarantinedPrefix;
    /** Set when a test decides to quarantine the newest release of an artifact. */
    private volatile String extraQuarantinedPath;
    private String newestCommonsIo;

    private HttpServer server;
    private ExecutorService serverPool;
    private String baseUrl;

    @BeforeEach
    void startStubFirewall() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        // HttpServer defaults to a single-threaded executor. Maven Resolver downloads in
        // parallel, so the default serialises every fetch behind one connection and turns a
        // few-second test into minutes.
        serverPool = Executors.newFixedThreadPool(8);
        server.setExecutor(serverPool);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            boolean wholeArtifactBlocked = quarantinedPrefix != null
                    && path.startsWith(quarantinedPrefix) && path.endsWith(".jar");
            if (QUARANTINED_PATH.equals(path) || path.equals(extraQuarantinedPath) || wholeArtifactBlocked) {
                byte[] body = QUARANTINE_BODY.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(403, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
                return;
            }
            proxyToCentral(exchange, path);
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
    }

    private void proxyToCentral(com.sun.net.httpserver.HttpExchange exchange, String path) {
        try {
            HttpResponse<byte[]> upstream = UPSTREAM.send(
                    HttpRequest.newBuilder(URI.create(
                            "https://repo.maven.apache.org/maven2" + path))
                            .timeout(Duration.ofSeconds(60)).GET().build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            byte[] body = upstream.body();
            exchange.sendResponseHeaders(upstream.statusCode(), body.length == 0 ? -1 : body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        } catch (Exception e) {
            try {
                exchange.sendResponseHeaders(502, -1);
            } catch (Exception ignored) {
                // The client went away; nothing useful to do.
            }
        } finally {
            exchange.close();
        }
    }

    @AfterEach
    void stopStubFirewall() {
        if (server != null) {
            server.stop(0);
        }
        if (serverPool != null) {
            serverPool.shutdownNow();
        }
    }

    /** Blocks the newest published release of an artifact, as a firewall would. */
    private void quarantineNewestVersionOf(String groupId, String artifactId) throws Exception {
        String metadata = new String(URI.create("https://repo.maven.apache.org/maven2/"
                + groupId.replace('.', '/') + "/" + artifactId + "/maven-metadata.xml")
                .toURL().openStream().readAllBytes(), StandardCharsets.UTF_8);
        java.util.regex.Matcher matcher =
                java.util.regex.Pattern.compile("<release>([^<]+)</release>").matcher(metadata);
        org.junit.jupiter.api.Assumptions.assumeTrue(matcher.find(), "no <release> in metadata");

        newestCommonsIo = matcher.group(1);
        extraQuarantinedPath = "/" + groupId.replace('.', '/') + "/" + artifactId + "/"
                + newestCommonsIo + "/" + artifactId + "-" + newestCommonsIo + ".jar";
    }

    /** Confirms the stub is reachable before drawing conclusions from a failure. */
    private void assumeStubUsable() {
        try (InputStream ignored = URI.create(baseUrl
                + "org/apache/commons/commons-text/1.11.0/commons-text-1.11.0.pom").toURL().openStream()) {
            // Reachable and proxying.
        } catch (Exception e) {
            org.junit.jupiter.api.Assumptions.abort("Maven Central not reachable through the stub: " + e);
        }
    }

    @Test
    @DisplayName("pins a quarantined component to the nearest version the firewall serves")
    void pinsQuarantinedComponent(@TempDir Path projectDir) throws Exception {
        assumeStubUsable();

        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>svc</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>org.apache.commons</groupId>
                <artifactId>commons-text</artifactId><version>1.10.0</version></dependency></dependencies>
                </project>
                """);

        ScanReport report = runEngine(projectDir, true);

        assertEquals(1, report.quarantined().size(), report.quarantined().toString());
        ScanReport.QuarantinedComponent component = report.quarantined().getFirst();

        assertEquals(ScanReport.Outcome.FIXED, component.outcome(), () -> component.notes().toString());
        assertEquals("org.apache.commons:commons-text:1.10.0", component.gav());
        assertNotNull(component.replacementVersion());
        assertTrue(VersionPolicy.compare(component.replacementVersion(), "1.10.0") > 0);

        // The firewall link is what a developer needs to decide bump-vs-waiver, so it must survive.
        assertEquals("https://iq.example.com/ui/links/firewall/repositories/"
                + "quarantinedComponent/ABCD1234EFGH5678", component.quarantineUrl());

        // The declared version is edited in place when possible; a dependencyManagement pin is
        // only used for artifacts that are not declared here. Either shape is fine — what must
        // hold is that the quarantined version is gone and the replacement is in the file.
        String rewritten = Files.readString(pom);
        assertTrue(rewritten.contains(component.replacementVersion()), rewritten);
        assertFalse(rewritten.contains("<version>1.10.0</version>"), rewritten);
    }

    @Test
    @DisplayName("downgrades when the quarantined version is the newest one published")
    void downgradesWhenNoNewerVersionExists(@TempDir Path projectDir) throws Exception {
        assumeStubUsable();

        // Mirrors the real case: kotlinx-metadata-jvm ends at 0.9.0 because Kotlin 2.0 renamed the
        // artifact, so the quarantined release is also the last one. Searching only upwards finds
        // nothing and leaves the build blocked; stepping back is the only available fix.
        quarantineNewestVersionOf("commons-io", "commons-io");

        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>svc</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>commons-io</groupId>
                <artifactId>commons-io</artifactId><version>%s</version></dependency></dependencies>
                </project>
                """.formatted(newestCommonsIo));

        ScanReport report = runEngine(projectDir, true);

        assertEquals(1, report.quarantined().size(), report.quarantined().toString());
        ScanReport.QuarantinedComponent component = report.quarantined().getFirst();

        assertEquals(ScanReport.Outcome.FIXED, component.outcome(), () -> component.notes().toString());
        assertTrue(VersionPolicy.compare(component.replacementVersion(), newestCommonsIo) < 0,
                "expected a downgrade, got " + component.replacementVersion());
        assertTrue(component.notes().stream().anyMatch(note -> note.contains("DOWNGRADE")),
                "a downgrade must be called out explicitly: " + component.notes());
    }

    @Test
    @DisplayName("pins an artifact the build needs but the dependency graph never mentions")
    void pinsArtifactOutsideTheDependencyGraph(@TempDir Path projectDir) throws Exception {
        assumeStubUsable();

        // The Quarkus case: the blocked artifact is resolved by the build, not by <dependencies>.
        // OpenRewrite's "only add if already used" guard cannot see such a classpath, so the edit
        // has to be made unconditionally or the build stays broken.
        Path pom = projectDir.resolve("pom.xml");
        Files.writeString(pom, """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>svc</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>commons-io</groupId>
                <artifactId>commons-io</artifactId><version>2.16.1</version></dependency></dependencies>
                </project>
                """);

        String log = "Could not transfer artifact org.apache.commons:commons-text:jar:1.10.0 "
                + "from/to nexus: status code: 403, reason phrase: REQUESTED ITEM IS QUARANTINED "
                + "SEE https://iq.example.com/ui/links/firewall/repositories/quarantinedComponent/XYZ";

        ScanReport report = runEngineWithBuildLog(projectDir, log);

        assertEquals(1, report.quarantined().size(), report.quarantined().toString());
        ScanReport.QuarantinedComponent component = report.quarantined().getFirst();

        assertEquals(ScanReport.Outcome.FIXED, component.outcome(), () -> component.notes().toString());
        assertTrue(component.notes().stream().anyMatch(n -> n.contains("not in the dependency graph")),
                component.notes().toString());

        String rewritten = Files.readString(pom);
        assertTrue(rewritten.contains("dependencyManagement"), rewritten);
        assertTrue(rewritten.contains("commons-text"), rewritten);
    }

    private ScanReport runEngineWithBuildLog(Path projectDir, String buildLog) throws Exception {
        NexusCredentials credentials = new NexusCredentials(baseUrl, null, null);
        RepositorySystem system = MavenResolverFactory.createRepositorySystem();
        RepositorySystemSession session = MavenResolverFactory.createSession(
                system, sharedLocalRepository, credentials, null);
        List<RemoteRepository> repositories =
                MavenResolverFactory.createRepositories(system, session, credentials, null);

        return new RemediationEngine(SonatypeScanReport.none(), system, session, repositories,
                credentials, projectDir,
                new RemediationEngine.Options(VersionPolicy.UpgradeScope.MINOR, false, false, 3,
                        false, true, false, buildLog, null, 5))
                .run(projectDir.resolve("pom.xml").toFile());
    }

    @Test
    @DisplayName("a quarantined component fails the gate no matter the severity threshold")
    void quarantineIsBlocking(@TempDir Path projectDir) throws Exception {
        assumeStubUsable();

        Files.writeString(projectDir.resolve("pom.xml"), """
                <?xml version="1.0" encoding="UTF-8"?>
                <project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId><artifactId>svc</artifactId><version>1.0.0</version>
                <dependencies><dependency><groupId>org.apache.commons</groupId>
                <artifactId>commons-text</artifactId><version>1.10.0</version></dependency></dependencies>
                </project>
                """);

        // Every version of the artifact is refused, so neither an upgrade nor a downgrade can
        // help. This is the only genuinely unremediable shape now that the search goes both ways.
        quarantinedPrefix = "/org/apache/commons/commons-text/";
        // A private local repository: the shared one already holds jars an earlier test fetched,
        // and a cache hit never reaches the stub, so the block would go unnoticed.
        ScanReport report = runEngine(projectDir, true, projectDir.resolve("private-repo"));

        assertTrue(report.hasBlockingQuarantine());
        assertEquals(1, report.unresolvedQuarantines().size());
    }

    private ScanReport runEngine(Path projectDir, boolean allowMinor) throws Exception {
        return runEngine(projectDir, allowMinor, sharedLocalRepository);
    }

    private ScanReport runEngine(Path projectDir, boolean allowMinor, Path localRepository)
            throws Exception {
        NexusCredentials credentials = new NexusCredentials(baseUrl, null, null);
        RepositorySystem system = MavenResolverFactory.createRepositorySystem();
        // A private local repository, so nothing is answered from an earlier download.
        RepositorySystemSession session = MavenResolverFactory.createSession(
                system, localRepository, credentials, null);
        List<RemoteRepository> repositories =
                MavenResolverFactory.createRepositories(system, session, credentials, null);

        SonatypeScanReport empty = new SonatypeScanReport("svc", "scan", null, 1, 0, List.of());
        return new RemediationEngine(empty, system, session, repositories, credentials, projectDir,
                new RemediationEngine.Options(
                        allowMinor ? VersionPolicy.UpgradeScope.MINOR : VersionPolicy.UpgradeScope.PATCH,
                        // Three candidates is plenty here and keeps the probe count — and so the
                        // number of real downloads through the stub — bounded.
                        false, false, 3, false, true, true, null, null, 5))
                .run(projectDir.resolve("pom.xml").toFile());
    }
}
