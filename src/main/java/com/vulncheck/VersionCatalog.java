package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.VersionRangeRequest;
import org.eclipse.aether.resolution.VersionRangeResolutionException;
import org.eclipse.aether.resolution.VersionRangeResult;
import org.eclipse.aether.version.Version;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Looks up the versions a repository publishes for an artifact.
 *
 * <p>Results are memoised for the lifetime of a run. A single scan asks for the same coordinates
 * repeatedly — once per vulnerability that shares a direct dependency, and again for each parent
 * or BOM — and every miss is a network round-trip to fetch {@code maven-metadata.xml}.
 */
public final class VersionCatalog {

    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession session;
    private final List<RemoteRepository> repositories;

    private final Map<String, List<String>> cache = new ConcurrentHashMap<>();

    public VersionCatalog(RepositorySystem repositorySystem,
                          RepositorySystemSession session,
                          List<RemoteRepository> repositories) {
        this.repositorySystem = repositorySystem;
        this.session = session;
        this.repositories = List.copyOf(repositories);
    }

    /**
     * All published versions of {@code groupId:artifactId}, ascending.
     *
     * <p>Returns an empty list rather than throwing when the repository has no metadata: a single
     * unpublishable artifact must not abort a scan of a hundred others. The reason is logged.
     */
    public List<String> availableVersions(String groupId, String artifactId, String extension) {
        String key = groupId + ":" + artifactId + ":" + extension;
        return cache.computeIfAbsent(key, k -> fetch(groupId, artifactId, extension));
    }

    private List<String> fetch(String groupId, String artifactId, String extension) {
        // An unbounded range asks the repository for the full metadata document; filtering
        // down to what the upgrade policy allows happens in VersionPolicy, not here.
        Artifact artifact = new DefaultArtifact(groupId, artifactId, extension, "[0,)");
        VersionRangeRequest request = new VersionRangeRequest(artifact, repositories, null);

        try {
            VersionRangeResult result = repositorySystem.resolveVersionRange(session, request);
            if (!result.getExceptions().isEmpty()) {
                Log.debug("Version lookup for %s:%s reported %d warning(s); first: %s",
                        groupId, artifactId, result.getExceptions().size(),
                        Log.describe(result.getExceptions().getFirst()));
            }
            List<String> versions = result.getVersions().stream().map(Version::toString).toList();
            Log.debug("%s:%s -> %d published version(s)", groupId, artifactId, versions.size());
            return versions;
        } catch (VersionRangeResolutionException e) {
            Log.debug("Could not list versions of %s:%s: %s", groupId, artifactId, Log.describe(e));
            return List.of();
        }
    }

    /**
     * Upgrade candidates for {@code currentVersion}, ascending, honouring {@code scope}
     * and excluding pre-releases.
     */
    public List<String> upgradeCandidates(String groupId, String artifactId, String extension,
                                          String currentVersion, VersionPolicy.UpgradeScope scope) {
        return VersionPolicy.candidates(
                availableVersions(groupId, artifactId, extension), currentVersion, scope);
    }
}
