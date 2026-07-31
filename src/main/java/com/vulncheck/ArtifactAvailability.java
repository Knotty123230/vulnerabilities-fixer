package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Answers whether a specific artifact version can actually be downloaded.
 *
 * <p>Metadata and reality disagree in firewalled environments. {@code maven-metadata.xml} lists
 * every version the upstream published, including ones the proxy will refuse with a quarantine
 * 403 — so a version chosen purely from metadata can be one that no build on this network can
 * fetch. Upgrading a POM to such a version trades a vulnerability for a broken build, which is a
 * bad trade and an unobvious one, because the POM looks correct.
 *
 * <p>The only reliable check is to request the artifact, so this class does exactly that and
 * caches the answer. Note the side effect: requesting a component the firewall has never seen is
 * what <em>causes</em> it to be evaluated and possibly quarantined. That is acceptable — a version
 * that quarantines on first sight is one this project must not adopt anyway — but it means probing
 * is not free of consequence, and it is why probing is scoped to versions actually under
 * consideration rather than to whole version ranges.
 */
public final class ArtifactAvailability {

    public enum Status {
        /** Downloaded successfully. */
        AVAILABLE,
        /** Refused by Sonatype Repository Firewall. */
        QUARANTINED,
        /** Rejected with 403 for a non-quarantine reason, typically credentials. */
        FORBIDDEN,
        /** Not published, or not carried by this repository. */
        MISSING,
        /** Something else went wrong; treated as unknown rather than unusable. */
        ERROR
    }

    public record Result(Status status, String quarantineUrl, String detail) {

        public boolean isUsable() {
            // ERROR is deliberately usable: a transient network failure must not silently
            // disqualify an otherwise valid version.
            return status == Status.AVAILABLE || status == Status.ERROR;
        }

        public boolean isQuarantined() {
            return status == Status.QUARANTINED;
        }
    }

    private static final Result AVAILABLE = new Result(Status.AVAILABLE, null, null);

    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession session;
    private final List<RemoteRepository> repositories;
    private final NexusCredentials credentials;
    private final HttpClient httpClient;
    private final Map<String, Result> cache = new ConcurrentHashMap<>();

    public ArtifactAvailability(RepositorySystem repositorySystem,
                                RepositorySystemSession session,
                                List<RemoteRepository> repositories) {
        this(repositorySystem, session, repositories, null);
    }

    public ArtifactAvailability(RepositorySystem repositorySystem,
                                RepositorySystemSession session,
                                List<RemoteRepository> repositories,
                                NexusCredentials credentials) {
        this.repositorySystem = repositorySystem;
        this.session = session;
        this.repositories = List.copyOf(repositories);
        this.credentials = credentials;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    public Result check(String groupId, String artifactId, String extension, String version) {
        return check(new DefaultArtifact(groupId, artifactId,
                extension == null || extension.isBlank() ? "jar" : extension, version));
    }

    /**
     * Resolves the artifact and classifies the outcome.
     *
     * <p>The JAR is probed rather than the POM on purpose: the firewall quarantines the component,
     * and a POM frequently passes through while the JAR beside it is blocked — which is exactly the
     * shape of the failure that breaks a build halfway through.
     */
    public Result check(Artifact artifact) {
        String key = artifact.getGroupId() + ":" + artifact.getArtifactId()
                + ":" + artifact.getExtension() + ":" + artifact.getVersion();

        return cache.computeIfAbsent(key, k -> {
            try {
                repositorySystem.resolveArtifact(session, new ArtifactRequest(artifact, repositories, null));
                Log.debug("Availability %s: AVAILABLE", k);
                return AVAILABLE;
            } catch (ArtifactResolutionException e) {
                Result result = classify(e);
                // The resolver may have thrown away the response body that says *why* it was
                // refused, so a 403 is re-checked directly before being labelled.
                if (result.status() == Status.FORBIDDEN) {
                    result = probeOverHttp(artifact).orElse(result);
                }
                Log.debug("Availability %s: %s", k, result.status());
                return result;
            } catch (RuntimeException e) {
                Log.debug("Availability %s: probe failed (%s)", k, Log.describe(e));
                return new Result(Status.ERROR, null, Log.describe(e));
            }
        });
    }

    private static Result classify(ArtifactResolutionException failure) {
        // The transport failure carrying the 403 body lives in the result, not the cause chain.
        List<Throwable> related = new ArrayList<>();
        related.add(failure);
        if (failure.getResult() != null) {
            related.addAll(failure.getResult().getExceptions());
        }

        QuarantineDetector.Verdict verdict = QuarantineDetector.inspect(related);
        if (verdict.quarantined()) {
            return new Result(Status.QUARANTINED, verdict.quarantineUrl(), verdict.detail());
        }
        if (verdict.forbidden()) {
            return new Result(Status.FORBIDDEN, null, verdict.detail());
        }

        String message = failure.getMessage() == null ? "" : failure.getMessage();
        if (message.contains("could not be resolved") || message.contains("was not found")) {
            return new Result(Status.MISSING, null, "not present in the repository");
        }
        return new Result(Status.ERROR, null, Log.describe(failure));
    }

    /**
     * The artifact's file in the local repository, resolving it if needed.
     * Empty when it cannot be fetched — including when the firewall refuses it.
     */
    public Optional<Path> localFile(Artifact artifact) {
        try {
            return Optional.ofNullable(
                    repositorySystem.resolveArtifact(session, new ArtifactRequest(artifact, repositories, null))
                            .getArtifact().getFile())
                    .map(File::toPath);
        } catch (ArtifactResolutionException | RuntimeException e) {
            Log.debug("Could not resolve %s for inspection: %s", artifact, e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Re-requests the artifact over plain HTTP to read the refusal message.
     *
     * <p>Resolver 2.x's Apache transport reduces a rejection to {@code HTTP Status: 403} and drops
     * the response body — but the body is the only thing that distinguishes a firewall quarantine
     * from wrong credentials, and they demand opposite responses: try another version, or stop and
     * fix the login. Maven 3.9's transport happened to keep the reason phrase, so this only matters
     * for the resolver embedded here.
     *
     * @return a refined result, or empty when the probe could not improve on what we already knew
     */
    private Optional<Result> probeOverHttp(Artifact artifact) {
        for (RemoteRepository repository : repositories) {
            String url = artifactUrl(repository.getUrl(), artifact);
            try {
                HttpRequest.Builder request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(30))
                        .header("Accept", "*/*")
                        .GET();
                if (credentials != null && credentials.isAuthenticated()) {
                    String basic = credentials.username() + ":" + credentials.password();
                    request.header("Authorization", "Basic " + Base64.getEncoder()
                            .encodeToString(basic.getBytes(StandardCharsets.UTF_8)));
                }

                HttpResponse<String> response =
                        httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 403) {
                    continue;
                }

                QuarantineDetector.Verdict verdict = QuarantineDetector.inspect(
                        new IllegalStateException("status code: 403 " + response.body()));
                if (verdict.quarantined()) {
                    return Optional.of(new Result(Status.QUARANTINED, verdict.quarantineUrl(),
                            verdict.detail()));
                }
                return Optional.of(new Result(Status.FORBIDDEN, null,
                        "repository returned 403 (check credentials or repository permissions)"));

            } catch (IOException | RuntimeException e) {
                Log.debug("HTTP probe of %s failed: %s", url, Log.describe(e));
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Optional.empty();
            }
        }
        return Optional.empty();
    }

    /** Standard Maven 2 repository layout path for an artifact. */
    static String artifactUrl(String repositoryUrl, Artifact artifact) {
        String base = repositoryUrl.endsWith("/") ? repositoryUrl : repositoryUrl + "/";
        String classifier = artifact.getClassifier() == null || artifact.getClassifier().isBlank()
                ? ""
                : "-" + artifact.getClassifier();
        return base
                + artifact.getGroupId().replace('.', '/') + "/"
                + artifact.getArtifactId() + "/"
                + artifact.getVersion() + "/"
                + artifact.getArtifactId() + "-" + artifact.getVersion() + classifier
                + "." + artifact.getExtension();
    }

    /**
     * The first version in {@code ascendingVersions} that can actually be downloaded.
     *
     * <p>Ascending order means the smallest acceptable move wins, matching how the rest of the tool
     * picks versions. Probing stops at the first hit, so a family whose next version is clean costs
     * one request.
     */
    public Optional<String> firstUsable(String groupId, String artifactId, String extension,
                                        List<String> ascendingVersions) {
        for (String version : ascendingVersions) {
            if (check(groupId, artifactId, extension, version).isUsable()) {
                return Optional.of(version);
            }
        }
        return Optional.empty();
    }
}
