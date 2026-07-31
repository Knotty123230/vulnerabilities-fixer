package com.vulncheck;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenCentralBomSearchTest {

    @Nested
    @DisplayName("groupIdAndAncestors")
    class Ancestors {

        @Test
        @DisplayName("walks up to where cross-groupId BOMs actually live")
        void walksUpToBomHome() {
            // jackson-bom lives under com.fasterxml.jackson, the parent of jackson-databind's own
            // com.fasterxml.jackson.core — this is exactly the case naming convention cannot find.
            assertEquals(
                    List.of("com.fasterxml.jackson.core", "com.fasterxml.jackson"),
                    MavenCentralBomSearch.groupIdAndAncestors("com.fasterxml.jackson.core"));

            // junit-bom lives under org.junit, the parent of org.junit.jupiter.
            assertEquals(
                    List.of("org.junit.jupiter", "org.junit"),
                    MavenCentralBomSearch.groupIdAndAncestors("org.junit.jupiter"));
        }

        @Test
        @DisplayName("stops before a bare single-segment root")
        void stopsBeforeBareRoot() {
            // Must not include "io" or "com" alone — g:io or g:com would return everything.
            assertEquals(List.of("io.netty"), MavenCentralBomSearch.groupIdAndAncestors("io.netty"));
            assertEquals(List.of("com"), MavenCentralBomSearch.groupIdAndAncestors("com"));
        }

        @Test
        @DisplayName("caps the walk at four levels")
        void capsAtFourLevels() {
            List<String> ancestors = MavenCentralBomSearch.groupIdAndAncestors("a.b.c.d.e.f.g");
            assertEquals(4, ancestors.size(), ancestors.toString());
        }
    }

    @Nested
    @DisplayName("search")
    class Search {

        private HttpServer server;
        private String baseUrl;

        @BeforeEach
        void start() throws Exception {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.start();
            baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @AfterEach
        void stop() {
            if (server != null) {
                server.stop(0);
            }
        }

        private void respondWith(String json) {
            server.createContext("/solrsearch/select", exchange -> {
                byte[] body = json.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
        }

        @Test
        @DisplayName("keeps only pom-packaged, BOM-shaped artifacts")
        void filtersToPomBomShaped() {
            // A real solrsearch response shape: a mix of a genuine BOM, a same-named jar library,
            // and an unrelated pom artifact that just isn't a BOM by name.
            respondWith("""
                    {"response": {"docs": [
                        {"g": "org.springframework.boot", "a": "spring-boot-dependencies", "p": "pom"},
                        {"g": "org.springframework.boot", "a": "spring-boot-starter", "p": "jar"},
                        {"g": "org.springframework.boot", "a": "spring-boot-configuration-processor", "p": "jar"},
                        {"g": "org.springframework.boot", "a": "spring-boot-parent", "p": "pom"}
                    ]}}
                    """);

            MavenCentralBomSearch search = new MavenCentralBomSearch(baseUrl + "/solrsearch/select");
            List<String> candidates = search.findBomShapedArtifacts("org.springframework.boot");

            assertTrue(candidates.contains("org.springframework.boot:spring-boot-dependencies"), candidates.toString());
            assertTrue(candidates.stream().noneMatch(c -> c.contains("spring-boot-starter")), candidates.toString());
            assertTrue(candidates.stream().noneMatch(c -> c.contains("configuration-processor")), candidates.toString());
        }

        @Test
        @DisplayName("recognises non-'bom'-named BOMs by other markers")
        void recognisesAlternateMarkers() {
            respondWith("""
                    {"response": {"docs": [
                        {"g": "io.vertx", "a": "vertx-stack-depchain", "p": "pom"},
                        {"g": "io.vertx", "a": "vertx-core", "p": "jar"}
                    ]}}
                    """);

            MavenCentralBomSearch search = new MavenCentralBomSearch(baseUrl + "/solrsearch/select");
            List<String> candidates = search.findBomShapedArtifacts("io.vertx");

            assertTrue(candidates.contains("io.vertx:vertx-stack-depchain"), candidates.toString());
        }

        @Test
        @DisplayName("an unreachable or failing search returns empty rather than throwing")
        void failsSoftly() {
            // No handler registered at all for this port's path -> 404, or connection refused if
            // the server were stopped; either way the caller must get an empty list, not a crash.
            MavenCentralBomSearch search = new MavenCentralBomSearch("http://127.0.0.1:1/nonexistent");
            List<String> candidates = search.findBomShapedArtifacts("com.example");
            assertEquals(List.of(), candidates);
        }
    }
}
