package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.DependencyVisitor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

/**
 * Detects families of artifacts that are meant to move together but have drifted apart.
 *
 * <p>Version skew inside a family is a runtime hazard rather than a cosmetic one: a
 * {@code netty-codec} compiled against one {@code netty-common} and resolved against another fails
 * with {@code NoSuchMethodError} at the first call that crosses the boundary — long after the build
 * went green.
 *
 * <p>The hard part is saying what a "family" is. Grouping by {@code groupId} alone is wrong:
 * {@code org.apache.commons:commons-lang3:3.12.0} and {@code org.apache.commons:commons-text:1.10.0}
 * share a group and are supposed to have different versions. So a family is defined by its BOM —
 * artifacts are only treated as lockstep when a published BOM pins them all to <em>the same</em>
 * version. That is precisely the shape of {@code netty-bom} or {@code jackson-bom}, and it excludes
 * groups whose artifacts are versioned independently.
 */
public final class VersionSkewDetector {

    /** A lockstep family whose members resolved at more than one version. */
    public record Skew(
            String groupId,
            Map<String, String> resolvedArtifacts,
            List<String> distinctVersions,
            String highestVersion,
            BomLocator.Bom bom
    ) {
        public String describe() {
            return groupId + " resolves at " + String.join(", ", distinctVersions);
        }

        public String bomCoordinate() {
            return bom == null ? null : bom.coordinate();
        }
    }

    private final BomLocator bomLocator;

    public VersionSkewDetector(BomLocator bomLocator) {
        this.bomLocator = bomLocator;
    }

    /**
     * Scans the resolved graph for skewed families.
     *
     * <p>Only groups that already show more than one version are considered, so the BOM lookups —
     * which are network calls — are bounded by the number of genuinely suspicious groups rather
     * than by the size of the graph.
     */
    public List<Skew> detect(DependencyNode root) {
        Map<String, Map<String, String>> byGroup = collectByGroup(root);
        List<Skew> skews = new ArrayList<>();

        for (Map.Entry<String, Map<String, String>> entry : byGroup.entrySet()) {
            String groupId = entry.getKey();
            Map<String, String> artifacts = entry.getValue();

            List<String> versions = distinctVersions(artifacts);
            if (versions.size() < 2) {
                continue;
            }

            String highest = versions.getLast();
            Optional<BomLocator.Bom> bom = bomLocator.findFor(groupId, artifacts.keySet(), highest);
            if (bom.isEmpty()) {
                Log.debug("%s has mixed versions %s but no BOM manages them all — not a lockstep family",
                        groupId, versions);
                continue;
            }
            if (!isLockstepFamily(bom.get(), groupId, artifacts.keySet())) {
                Log.debug("%s is managed by %s but at differing versions — versioned independently",
                        groupId, bom.get().coordinate());
                continue;
            }

            skews.add(new Skew(groupId, Map.copyOf(artifacts), versions, highest, bom.get()));
            Log.debug("Version skew: %s (BOM %s)", groupId, bom.get().gav());
        }
        return List.copyOf(skews);
    }

    /**
     * Whether the BOM pins every one of these artifacts to a single shared version — the signature
     * of a family that ships as a unit.
     */
    private static boolean isLockstepFamily(BomLocator.Bom bom, String groupId, Set<String> artifactIds) {
        Set<String> managedVersions = artifactIds.stream()
                .map(artifact -> bom.managedVersionOf(groupId, artifact))
                .filter(java.util.Objects::nonNull)
                .collect(Collectors.toSet());
        return managedVersions.size() == 1;
    }

    /** {@code groupId -> (artifactId -> resolved version)} for the whole graph. */
    private static Map<String, Map<String, String>> collectByGroup(DependencyNode root) {
        Map<String, Map<String, String>> byGroup = new TreeMap<>();

        root.accept(new DependencyVisitor() {
            @Override
            public boolean visitEnter(DependencyNode node) {
                Artifact artifact = node.getArtifact();
                if (node != root && artifact != null) {
                    byGroup.computeIfAbsent(artifact.getGroupId(), g -> new LinkedHashMap<>())
                            .putIfAbsent(artifact.getArtifactId(), artifact.getVersion());
                }
                return true;
            }

            @Override
            public boolean visitLeave(DependencyNode node) {
                return true;
            }
        });
        return byGroup;
    }

    private static List<String> distinctVersions(Map<String, String> artifacts) {
        return artifacts.values().stream()
                .distinct()
                .sorted(VersionPolicy.ascending())
                .toList();
    }
}
