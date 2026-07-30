package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactDescriptorException;
import org.eclipse.aether.resolution.ArtifactDescriptorRequest;
import org.eclipse.aether.resolution.ArtifactDescriptorResult;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds the bill-of-materials that governs a family of artifacts.
 *
 * <p>There is no standard mapping from a groupId to its BOM, so candidates are guessed from
 * naming convention plus a small curated table, and then <b>verified by reading the descriptor</b>.
 * Verification is the important half: {@code io.netty:netty-bom} exists, but
 * {@code ch.qos.logback} publishes {@code logback-parent} — a parent POM, not a curated BOM — and
 * a convention-only guess would happily import something that manages nothing we care about.
 */
public final class BomLocator {

    /** Coordinates that convention alone would not find. */
    private static final Map<String, String> KNOWN_BOMS = Map.ofEntries(
            Map.entry("com.fasterxml.jackson.core", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.datatype", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.dataformat", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.module", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("org.springframework", "org.springframework:spring-framework-bom"),
            Map.entry("io.netty", "io.netty:netty-bom"),
            Map.entry("org.slf4j", "org.slf4j:slf4j-bom"),
            Map.entry("io.grpc", "io.grpc:grpc-bom"),
            Map.entry("com.google.protobuf", "com.google.protobuf:protobuf-bom"),
            Map.entry("io.projectreactor", "io.projectreactor:reactor-bom"),
            Map.entry("org.junit.jupiter", "org.junit:junit-bom"),
            Map.entry("org.testcontainers", "org.testcontainers:testcontainers-bom"),
            Map.entry("software.amazon.awssdk", "software.amazon.awssdk:bom"));

    /** A BOM together with the versions it pins, keyed by {@code group:artifact}. */
    public record Bom(String groupId, String artifactId, String version, Map<String, String> managedVersions) {

        public String coordinate() {
            return groupId + ":" + artifactId;
        }

        public String gav() {
            return coordinate() + ":" + version;
        }

        public String managedVersionOf(String group, String artifact) {
            return managedVersions.get(group + ":" + artifact);
        }

        public boolean manages(String group, String artifact) {
            return managedVersions.containsKey(group + ":" + artifact);
        }
    }

    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession session;
    private final List<RemoteRepository> repositories;
    private final VersionCatalog versionCatalog;

    /** Descriptor reads are network calls; a scan asks for the same BOM many times. */
    private final Map<String, Optional<Bom>> descriptorCache = new ConcurrentHashMap<>();

    public BomLocator(RepositorySystem repositorySystem,
                      RepositorySystemSession session,
                      List<RemoteRepository> repositories,
                      VersionCatalog versionCatalog) {
        this.repositorySystem = repositorySystem;
        this.session = session;
        this.repositories = List.copyOf(repositories);
        this.versionCatalog = versionCatalog;
    }

    /**
     * Candidate BOM coordinates for a group, most likely first.
     *
     * <p>Convention covers most publishers: {@code io.netty} → {@code io.netty:netty-bom},
     * {@code io.grpc} → {@code io.grpc:grpc-bom}.
     */
    static List<String> candidateCoordinates(String groupId, Set<String> artifactIds) {
        Set<String> candidates = new LinkedHashSet<>();

        String known = KNOWN_BOMS.get(groupId);
        if (known != null) {
            candidates.add(known);
        }

        String lastSegment = groupId.substring(groupId.lastIndexOf('.') + 1);
        candidates.add(groupId + ":" + lastSegment + "-bom");
        candidates.add(groupId + ":bom");

        // Artifacts frequently share a prefix that names the project: netty-codec, netty-handler.
        String prefix = commonPrefix(artifactIds);
        if (prefix != null && !prefix.isBlank()) {
            candidates.add(groupId + ":" + prefix + "-bom");
        }
        return List.copyOf(candidates);
    }

    /** Longest leading {@code -}-delimited segment shared by every artifact id. */
    private static String commonPrefix(Set<String> artifactIds) {
        if (artifactIds.isEmpty()) {
            return null;
        }
        String first = artifactIds.iterator().next();
        int dash = first.indexOf('-');
        String prefix = dash < 0 ? first : first.substring(0, dash);
        return artifactIds.stream().allMatch(id -> id.equals(prefix) || id.startsWith(prefix + "-"))
                ? prefix
                : null;
    }

    /**
     * Finds a BOM for {@code groupId} that manages at least the given artifacts.
     *
     * @param preferredVersion a version to aim for; the closest available BOM version at or above
     *                         it is used, so the family is never silently downgraded
     */
    public Optional<Bom> findFor(String groupId, Set<String> artifactIds, String preferredVersion) {
        for (String coordinate : candidateCoordinates(groupId, artifactIds)) {
            String[] parts = coordinate.split(":");
            Optional<Bom> bom = load(parts[0], parts[1], preferredVersion);
            if (bom.isPresent() && managesAll(bom.get(), groupId, artifactIds)) {
                Log.debug("BOM for %s: %s", groupId, bom.get().gav());
                return bom;
            }
        }
        Log.debug("No BOM found that manages %s:%s", groupId, artifactIds);
        return Optional.empty();
    }

    private static boolean managesAll(Bom bom, String groupId, Set<String> artifactIds) {
        return artifactIds.stream().allMatch(artifact -> bom.manages(groupId, artifact));
    }

    /** All published versions of a BOM, ascending. Empty when the coordinate does not exist. */
    public List<String> availableVersions(String bomGroupId, String bomArtifactId) {
        return versionCatalog.availableVersions(bomGroupId, bomArtifactId, "pom");
    }

    /**
     * Reads a BOM descriptor at the lowest available version that is not below
     * {@code preferredVersion}.
     */
    private Optional<Bom> load(String bomGroupId, String bomArtifactId, String preferredVersion) {
        List<String> versions = availableVersions(bomGroupId, bomArtifactId);
        if (versions.isEmpty()) {
            return Optional.empty();
        }

        String chosen = versions.stream()
                .filter(v -> !VersionPolicy.isPreRelease(v))
                .filter(v -> preferredVersion == null || VersionPolicy.compare(v, preferredVersion) >= 0)
                .min(VersionPolicy.ascending())
                .orElseGet(() -> versions.getLast());

        return read(bomGroupId, bomArtifactId, chosen);
    }

    /** Reads the managed dependencies of one specific BOM version. */
    public Optional<Bom> read(String bomGroupId, String bomArtifactId, String version) {
        String key = bomGroupId + ":" + bomArtifactId + ":" + version;
        return descriptorCache.computeIfAbsent(key, k -> {
            ArtifactDescriptorRequest request = new ArtifactDescriptorRequest(
                    new DefaultArtifact(bomGroupId, bomArtifactId, "pom", version), repositories, null);
            try {
                ArtifactDescriptorResult result =
                        repositorySystem.readArtifactDescriptor(session, request);

                Map<String, String> managed = new LinkedHashMap<>();
                result.getManagedDependencies().forEach(dependency -> managed.putIfAbsent(
                        dependency.getArtifact().getGroupId() + ":" + dependency.getArtifact().getArtifactId(),
                        dependency.getArtifact().getVersion()));

                if (managed.isEmpty()) {
                    return Optional.empty();
                }
                return Optional.of(new Bom(bomGroupId, bomArtifactId, version, Map.copyOf(managed)));
            } catch (ArtifactDescriptorException e) {
                Log.debug("Could not read BOM %s: %s", k, e.getMessage());
                return Optional.empty();
            }
        });
    }

    /**
     * BOM versions worth trying, ascending, that keep the family at or above
     * {@code lowestAcceptableVersion}.
     */
    public List<String> upgradeCandidates(Bom bom, String lowestAcceptableVersion,
                                          VersionPolicy.UpgradeScope scope) {
        List<String> all = availableVersions(bom.groupId(), bom.artifactId());
        List<String> candidates = new ArrayList<>(
                VersionPolicy.candidates(all, lowestAcceptableVersion, scope));
        // The version already resolved is a legitimate target too: importing the BOM at the
        // family's current version aligns the stragglers without moving anyone forward.
        if (all.contains(lowestAcceptableVersion) && !candidates.contains(lowestAcceptableVersion)) {
            candidates.addFirst(lowestAcceptableVersion);
        }
        return List.copyOf(candidates);
    }
}
