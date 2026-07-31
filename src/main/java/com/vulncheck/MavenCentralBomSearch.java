package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds candidate BOM coordinates by querying Maven Central's public search index, instead of
 * relying only on naming convention or a hand-maintained list.
 *
 * <p>Neither convention nor a curated table can keep up with how many BOMs actually exist — new
 * ones are published constantly, and plenty of well-known ones do not even follow the {@code -bom}
 * naming convention: {@code org.springframework.boot:spring-boot-dependencies} and
 * {@code io.vertx:vertx-stack-depchain} are both real BOMs whose names contain neither "bom" nor
 * any single common marker. What generalises is where a BOM lives: its groupId is almost always
 * the same as, or an ancestor of, the groupId of what it manages — {@code jackson-bom} sits under
 * {@code com.fasterxml.jackson}, the parent of {@code com.fasterxml.jackson.core} where
 * {@code jackson-databind} actually lives; {@code junit-bom} sits under {@code org.junit}, the
 * parent of {@code org.junit.jupiter}. Searching each ancestor groupId for {@code pom}-packaged
 * artifacts with a BOM-shaped name finds these without having to know about them in advance.
 *
 * <p>This class only ever <em>proposes</em> candidates. Every hit still goes through the same
 * descriptor-based verification as a convention guess or a curated entry — reading the POM and
 * confirming it actually manages the artifacts in question — so a wrong guess here costs one extra
 * HTTP request, never a false positive import.
 */
final class MavenCentralBomSearch {

    private static final String DEFAULT_SEARCH_URL = "https://search.maven.org/solrsearch/select";

    /** Substrings that, case-insensitively, mark an artifactId as BOM-shaped. */
    private static final List<String> BOM_NAME_MARKERS = List.of(
            "bom", "dependencies", "platform", "depchain", "stack", "bill-of-materials");

    private final String searchUrl;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** One HTTP round trip per groupId for the lifetime of a run; a skew scan asks repeatedly. */
    private final Map<String, List<String>> cache = new ConcurrentHashMap<>();

    MavenCentralBomSearch() {
        this(DEFAULT_SEARCH_URL);
    }

    /** @param searchUrl override point for tests; production code always uses the public index. */
    MavenCentralBomSearch(String searchUrl) {
        this.searchUrl = searchUrl;
    }

    /**
     * {@code group:artifact} coordinates of every {@code pom}-packaged, BOM-shaped artifact
     * published directly under {@code groupId}.
     *
     * <p>Never throws: a network hiccup here should not abort a scan, it should just mean this
     * particular discovery channel found nothing this time. Convention guesses and the curated
     * table are tried first by the caller, so a search failure rarely costs the final answer.
     */
    List<String> findBomShapedArtifacts(String groupId) {
        return cache.computeIfAbsent(groupId, this::search);
    }

    private List<String> search(String groupId) {
        try {
            String query = "g:" + URLEncoder.encode(groupId, StandardCharsets.UTF_8);
            URI uri = URI.create(searchUrl + "?q=" + query + "&rows=200&wt=json");
            HttpRequest request = HttpRequest.newBuilder(uri)
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() != 200) {
                Log.debug("Maven Central search for g:%s returned HTTP %d", groupId, response.statusCode());
                return List.of();
            }

            SearchResponse parsed = objectMapper.readValue(response.body(), SearchResponse.class);
            List<String> candidates = parsed.response().docs().stream()
                    .filter(doc -> "pom".equals(doc.p()))
                    .filter(doc -> looksLikeBom(doc.a()))
                    .map(doc -> doc.g() + ":" + doc.a())
                    .distinct()
                    .toList();

            if (!candidates.isEmpty()) {
                Log.debug("Maven Central search for g:%s found %d BOM-shaped candidate(s): %s",
                        groupId, candidates.size(), candidates);
            }
            return candidates;

        } catch (Exception e) {
            Log.debug("Maven Central search for g:%s failed: %s", groupId, Log.describe(e));
            return List.of();
        }
    }

    private static boolean looksLikeBom(String artifactId) {
        String lower = artifactId.toLowerCase(Locale.ROOT);
        return BOM_NAME_MARKERS.stream().anyMatch(lower::contains);
    }

    /**
     * {@code groupId} together with each of its ancestors, closest first — {@code
     * "com.fasterxml.jackson.core"} yields {@code ["com.fasterxml.jackson.core",
     * "com.fasterxml.jackson", "com.fasterxml"]}.
     *
     * <p>Stops before a bare single-segment root: searching {@code g:com} or {@code g:org} alone
     * would return an unbounded, useless result set. Also capped at four levels — a BOM five
     * levels up from what it manages would not plausibly be found by this heuristic anyway, and by
     * then the guess is doing more harm (slow, noisy) than good.
     */
    static List<String> groupIdAndAncestors(String groupId) {
        List<String> result = new ArrayList<>();
        String current = groupId;
        while (true) {
            result.add(current);
            if (result.size() >= 4) {
                break;
            }
            int lastDot = current.lastIndexOf('.');
            if (lastDot < 0) {
                break;
            }
            String parent = current.substring(0, lastDot);
            if (parent.indexOf('.') < 0) {
                break;
            }
            current = parent;
        }
        return List.copyOf(result);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record SearchResponse(ResponseBody response) {
        private SearchResponse {
            response = response == null ? new ResponseBody(List.of()) : response;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record ResponseBody(List<Doc> docs) {
        private ResponseBody {
            docs = docs == null ? List.of() : List.copyOf(docs);
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private record Doc(String g, String a, String p) {
    }
}
