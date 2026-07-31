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
 * <p>There is no standard mapping from a groupId to its BOM, so candidates come from three sources,
 * tried in order of how cheap and how likely each one is to be right:
 * <ol>
 *   <li><b>Naming convention</b> — {@code io.netty} → {@code io.netty:netty-bom}. Free, and
 *       correct often enough to be worth trying first.</li>
 *   <li><b>A curated table</b> — for well-known publishers whose BOM lives under a different
 *       groupId or a name convention would not guess (Jackson, Spring Boot, AWS, ...).</li>
 *   <li><b>{@link MavenCentralBomSearch}</b> — when neither of the above finds anything, search
 *       Central directly for {@code pom}-packaged, BOM-shaped artifacts under the target's groupId
 *       and its ancestors. This is what actually scales to "every BOM that exists": the curated
 *       table only ever covers what someone thought to add to it, while the search generalises
 *       from where BOMs conventionally live relative to what they manage.</li>
 * </ol>
 *
 * <p>None of that is trusted on its own — every candidate is <b>verified by reading its
 * descriptor</b>. Verification is the important half: {@code io.netty:netty-bom} exists, but
 * {@code ch.qos.logback} publishes {@code logback-parent} — a parent POM, not a curated BOM — and
 * an unverified guess would happily import something that manages nothing we care about.
 */
public final class BomLocator {

    /**
     * Coordinates for well-known publishers that naming convention would not find on its own —
     * typically because the BOM lives under a different (usually shorter, ancestor) groupId than
     * the artifacts it manages, or uses a name that does not follow the {@code -bom} pattern.
     *
     * <p>This list is deliberately not exhaustive — {@link MavenCentralBomSearch} exists precisely
     * so it does not need to be. It exists to skip a network round trip for the publishers a scan
     * runs into constantly.
     */
    private static final Map<String, String> KNOWN_BOMS = Map.ofEntries(
            // Jackson: BOM groupId is the ancestor of every module's own groupId.
            Map.entry("com.fasterxml.jackson.core", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.datatype", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.dataformat", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.module", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.jaxrs", "com.fasterxml.jackson:jackson-bom"),
            Map.entry("com.fasterxml.jackson.jr", "com.fasterxml.jackson:jackson-bom"),

            // Spring ecosystem: each project publishes its own BOM under its own groupId, and the
            // name is "-dependencies" or "-bom" depending on the project, not one single pattern.
            Map.entry("org.springframework", "org.springframework:spring-framework-bom"),
            Map.entry("org.springframework.boot", "org.springframework.boot:spring-boot-dependencies"),
            Map.entry("org.springframework.cloud", "org.springframework.cloud:spring-cloud-dependencies"),
            Map.entry("org.springframework.security", "org.springframework.security:spring-security-bom"),
            Map.entry("org.springframework.integration", "org.springframework.integration:spring-integration-bom"),

            // JUnit 5: BOM groupId "org.junit" is the ancestor of jupiter/platform/vintage.
            Map.entry("org.junit.jupiter", "org.junit:junit-bom"),
            Map.entry("org.junit.platform", "org.junit:junit-bom"),
            Map.entry("org.junit.vintage", "org.junit:junit-bom"),

            // Cloud SDKs: each vendor's BOM artifactId does not follow a shared pattern.
            Map.entry("software.amazon.awssdk", "software.amazon.awssdk:bom"),
            Map.entry("com.amazonaws", "com.amazonaws:aws-java-sdk-bom"),
            Map.entry("com.google.cloud", "com.google.cloud:libraries-bom"),
            Map.entry("com.azure", "com.azure:azure-sdk-bom"),

            // Kotlin: BOM lives under the same groupId as the compiler/stdlib artifacts.
            Map.entry("org.jetbrains.kotlin", "org.jetbrains.kotlin:kotlin-bom"),
            // A separate, differently-versioned family under the same top-level org.
            Map.entry("org.jetbrains.kotlinx", "org.jetbrains.kotlinx:kotlinx-coroutines-bom"),

            // Frameworks whose BOM name breaks the "-bom" convention outright.
            Map.entry("io.vertx", "io.vertx:vertx-stack-depchain"),
            Map.entry("io.micronaut", "io.micronaut.platform:micronaut-platform"),
            Map.entry("io.quarkus", "io.quarkus:quarkus-bom"),
            Map.entry("jakarta.platform", "jakarta.platform:jakarta.jakartaee-bom"),

            // Widely-used libraries whose BOM naming convention alone would still find, but that
            // are common enough to be worth skipping the network round trip for.
            Map.entry("io.netty", "io.netty:netty-bom"),
            Map.entry("org.slf4j", "org.slf4j:slf4j-bom"),
            Map.entry("io.grpc", "io.grpc:grpc-bom"),
            Map.entry("com.google.protobuf", "com.google.protobuf:protobuf-bom"),
            Map.entry("io.projectreactor", "io.projectreactor:reactor-bom"),
            Map.entry("io.projectreactor.netty", "io.projectreactor:reactor-bom"),
            Map.entry("org.testcontainers", "org.testcontainers:testcontainers-bom"),
            Map.entry("org.mockito", "org.mockito:mockito-bom"),
            Map.entry("org.assertj", "org.assertj:assertj-bom"),
            Map.entry("io.cucumber", "io.cucumber:cucumber-bom"),
            Map.entry("org.apache.logging.log4j", "org.apache.logging.log4j:log4j-bom"),
            Map.entry("io.opentelemetry", "io.opentelemetry:opentelemetry-bom"),
            Map.entry("io.micrometer", "io.micrometer:micrometer-bom"),
            Map.entry("io.github.resilience4j", "io.github.resilience4j:resilience4j-bom"),
            Map.entry("org.glassfish.jersey", "org.glassfish.jersey:jersey-bom"),
            Map.entry("org.jboss.resteasy", "org.jboss.resteasy:resteasy-bom"),
            Map.entry("org.apache.cxf", "org.apache.cxf:cxf-bom"),
            Map.entry("org.apache.camel", "org.apache.camel:camel-bom"),
            Map.entry("io.dropwizard.metrics", "io.dropwizard.metrics:metrics-bom"),
            Map.entry("org.mongodb", "org.mongodb:mongodb-driver-bom"),
            Map.entry("com.datastax.oss", "com.datastax.oss:java-driver-bom"),
            Map.entry("com.vaadin", "com.vaadin:vaadin-bom"));

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
    private final MavenCentralBomSearch centralSearch = new MavenCentralBomSearch();

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
            Optional<Bom> bom = tryCandidate(coordinate, groupId, artifactIds, preferredVersion);
            if (bom.isPresent()) {
                Log.debug("BOM for %s: %s (convention or curated table)", groupId, bom.get().gav());
                return bom;
            }
        }

        // Neither convention nor the curated table found a working candidate. Rather than give up,
        // ask Maven Central directly — this is what makes the lookup cover BOMs nobody thought to
        // add to the table, at the cost of one search request per ancestor groupId (cached, and
        // only reached for groups a scan has already flagged as genuinely skewed).
        for (String groupIdToSearch : MavenCentralBomSearch.groupIdAndAncestors(groupId)) {
            for (String coordinate : centralSearch.findBomShapedArtifacts(groupIdToSearch)) {
                Optional<Bom> bom = tryCandidate(coordinate, groupId, artifactIds, preferredVersion);
                if (bom.isPresent()) {
                    Log.debug("BOM for %s: %s (found via Maven Central search)", groupId, bom.get().gav());
                    return bom;
                }
            }
        }

        Log.debug("No BOM found that manages %s:%s (tried convention, curated table, and search)",
                groupId, artifactIds);
        return Optional.empty();
    }

    private Optional<Bom> tryCandidate(String coordinate, String groupId, Set<String> artifactIds,
                                       String preferredVersion) {
        String[] parts = coordinate.split(":");
        if (parts.length != 2) {
            return Optional.empty();
        }
        Optional<Bom> bom = load(parts[0], parts[1], preferredVersion);
        return bom.filter(candidate -> managesAll(candidate, groupId, artifactIds));
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
