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
            if (QUARANTINED_PATH.equals(path)) {
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

        // PATCH scope leaves no candidate on the 1.10.x line, so it cannot be remediated.
        ScanReport report = runEngine(projectDir, false);

        assertTrue(report.hasBlockingQuarantine());
        assertEquals(1, report.unresolvedQuarantines().size());
    }

    private ScanReport runEngine(Path projectDir, boolean allowMinor) throws Exception {
        NexusCredentials credentials = new NexusCredentials(baseUrl, null, null);
        RepositorySystem system = MavenResolverFactory.createRepositorySystem();
        // A private local repository, so nothing is answered from an earlier download.
        RepositorySystemSession session = MavenResolverFactory.createSession(
                system, projectDir.resolve("local-repo"), credentials, null);
        List<RemoteRepository> repositories =
                MavenResolverFactory.createRepositories(system, session, credentials, null);

        SonatypeScanReport empty = new SonatypeScanReport("svc", "scan", null, 1, 0, List.of());
        return new RemediationEngine(empty, system, session, repositories, credentials, projectDir,
                new RemediationEngine.Options(
                        allowMinor ? VersionPolicy.UpgradeScope.MINOR : VersionPolicy.UpgradeScope.PATCH,
                        // Three candidates is plenty here and keeps the probe count — and so the
                        // number of real downloads through the stub — bounded.
                        false, false, 3, false, true, true))
                .run(projectDir.resolve("pom.xml").toFile());
    }
}
