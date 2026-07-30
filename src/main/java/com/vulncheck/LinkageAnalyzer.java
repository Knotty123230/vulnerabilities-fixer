package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.util.graph.visitor.PreorderNodeListGenerator;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Decides whether a proposed dependency upgrade would break binary compatibility.
 *
 * <p>The check is <b>differential</b>. A codebase almost always contains references that a static
 * checker cannot satisfy — optional dependencies that were never on the classpath, {@code provided}
 * scope, reflective shims, soft-dependency patterns like {@code slf4j}. Reporting those as errors
 * makes the tool cry wolf and get switched off. So the same targets are scanned twice, against the
 * classpath before the upgrade and after it, and only symbols that <em>stopped</em> resolving are
 * treated as regressions caused by the change.
 *
 * <p>Scanning is scoped to the artifacts that can actually be affected: the project's own classes
 * plus the JARs of every dependency that (transitively) consumes the upgraded artifact. Scanning
 * the whole classpath would be far slower and would surface breakage that has nothing to do with
 * this change.
 */
public final class LinkageAnalyzer {

    /** Outcome of comparing a baseline classpath against a candidate one. */
    public record Verdict(boolean compatible, List<ClassLinkageChecker.Finding> regressions, String skipReason) {

        static Verdict skipped(String reason) {
            return new Verdict(true, List.of(), reason);
        }

        static Verdict of(List<ClassLinkageChecker.Finding> regressions) {
            return new Verdict(!ClassLinkageChecker.hasBreakingFinding(regressions), regressions, null);
        }

        public boolean wasSkipped() {
            return skipReason != null;
        }

        public List<String> renderRegressions(int limit) {
            return regressions.stream()
                    .sorted((a, b) -> a.severity().compareTo(b.severity()))
                    .limit(limit)
                    .map(ClassLinkageChecker.Finding::render)
                    .toList();
        }
    }

    private final LocalProjectAnalyzer analyzer;
    private final Path projectPath;

    /** Baseline symbol failures, keyed by {@link ClassLinkageChecker.Finding#key()}. */
    private Set<String> baselineKeys;
    /** {@code group:artifact:version} of every JAR the baseline scan actually read. */
    private Set<String> baselineScannedGavs;
    private String baselineSkipReason;

    public LinkageAnalyzer(LocalProjectAnalyzer analyzer, Path projectPath) {
        this.analyzer = analyzer;
        this.projectPath = projectPath;
    }

    /**
     * Records the pre-change state. Done once per run and reused for every candidate version,
     * because resolving a full classpath means downloading every JAR.
     */
    public void establishBaseline(DependencyNode collectedRoot, String groupId, String artifactId) {
        Path ownClasses = projectPath.resolve("target/classes");
        if (!Files.isDirectory(ownClasses)) {
            baselineSkipReason = "target/classes not found — run `mvn compile` first to enable the "
                    + "binary-compatibility check";
            Log.debug(baselineSkipReason);
            return;
        }
        try {
            Scan scan = scan(collectedRoot, groupId, artifactId, null);
            baselineKeys = scan.findings().stream()
                    .map(ClassLinkageChecker.Finding::key)
                    .collect(Collectors.toSet());
            baselineScannedGavs = scan.scannedGavs();
            Log.debug("Linkage baseline: %d pre-existing unresolved reference(s) across %d artifact(s)",
                    baselineKeys.size(), baselineScannedGavs.size());
        } catch (Exception e) {
            baselineSkipReason = "could not establish a linkage baseline: " + Log.describe(e);
            Log.debug(baselineSkipReason);
        }
    }

    /**
     * Compares a candidate graph against the baseline.
     *
     * <p>Returns a compatible verdict when no baseline could be established: refusing an
     * otherwise-valid security fix because the check could not run would be the wrong default.
     */
    public Verdict verify(DependencyNode candidateRoot, String groupId, String artifactId) {
        if (baselineKeys == null) {
            return Verdict.skipped(baselineSkipReason != null ? baselineSkipReason : "no baseline available");
        }
        try {
            List<ClassLinkageChecker.Finding> regressions =
                    scan(candidateRoot, groupId, artifactId, baselineScannedGavs).findings().stream()
                            .filter(f -> !baselineKeys.contains(f.key()))
                            .toList();
            return Verdict.of(regressions);
        } catch (Exception e) {
            Log.debug("Linkage verification failed: %s", Log.describe(e));
            return Verdict.skipped("binary-compatibility check failed to run: " + Log.describe(e));
        }
    }

    // ------------------------------------------------------------------

    private record Scan(List<ClassLinkageChecker.Finding> findings, Set<String> scannedGavs) {
    }

    /**
     * Indexes the resolved classpath and scans the code that could be affected by the change.
     *
     * @param comparableGavs when non-null, restricts dependency scan targets to artifacts whose
     *                       {@code group:artifact:version} the baseline also scanned. This is what
     *                       makes the diff sound: an artifact that changed version has different
     *                       bytecode in the two runs, so <em>every</em> difference in its findings
     *                       would look like a regression — including new optional-dependency
     *                       references that were never resolvable and never will be. Only
     *                       byte-identical scan targets can be meaningfully compared.
     */
    private Scan scan(DependencyNode collectedRoot, String groupId, String artifactId,
                      Set<String> comparableGavs) throws Exception {
        DependencyNode resolvedRoot = analyzer.resolveArtifacts(collectedRoot);

        PreorderNodeListGenerator classpath = new PreorderNodeListGenerator();
        resolvedRoot.accept(classpath);

        List<Path> fullClasspath = classpath.getFiles().stream()
                .map(File::toPath)
                .toList();
        if (fullClasspath.isEmpty()) {
            throw new IllegalStateException("resolved classpath is empty");
        }

        Set<String> consumers = findConsumersOf(resolvedRoot, groupId + ":" + artifactId);

        // The project's own classes are the primary target: they are identical in both runs by
        // construction, so any reference that stops resolving is unambiguously caused by the change.
        List<Path> scanTargets = new ArrayList<>();
        scanTargets.add(projectPath.resolve("target/classes"));

        Set<String> scannedGavs = new HashSet<>();
        for (DependencyNode node : classpath.getNodes()) {
            Artifact artifact = node.getArtifact();
            if (artifact == null || artifact.getFile() == null) {
                continue;
            }
            if (!consumers.contains(artifact.getGroupId() + ":" + artifact.getArtifactId())) {
                continue;
            }
            String gav = artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion();
            if (comparableGavs != null && !comparableGavs.contains(gav)) {
                Log.debug("Excluding %s from the linkage diff — its own version changed", gav);
                continue;
            }
            scanTargets.add(artifact.getFile().toPath());
            scannedGavs.add(gav);
        }

        ClassLinkageChecker checker = new ClassLinkageChecker();
        checker.indexClasspath(fullClasspath);
        Log.debug("Linkage scan: %d classpath entries, %d scan target(s)", fullClasspath.size(), scanTargets.size());
        return new Scan(checker.scanReferences(scanTargets), scannedGavs);
    }

    /**
     * Every artifact on a path from the project root down to {@code targetGA} — i.e. everything
     * that could hold a compiled reference into the upgraded artifact.
     */
    private Set<String> findConsumersOf(DependencyNode root, String targetGA) {
        Map<DependencyNode, DependencyNode> parentOf = new IdentityHashMap<>();
        buildParentMap(root, null, parentOf, java.util.Collections.newSetFromMap(new IdentityHashMap<>()));

        List<DependencyNode> targets = new ArrayList<>();
        collectNodesByGA(root, targetGA, targets, java.util.Collections.newSetFromMap(new IdentityHashMap<>()));

        Set<String> consumers = new HashSet<>();
        Deque<DependencyNode> queue = new ArrayDeque<>(targets);
        Set<DependencyNode> visited = java.util.Collections.newSetFromMap(new IdentityHashMap<>());

        while (!queue.isEmpty()) {
            DependencyNode node = queue.poll();
            if (!visited.add(node)) {
                continue;
            }
            Artifact artifact = node.getArtifact();
            if (artifact != null) {
                consumers.add(artifact.getGroupId() + ":" + artifact.getArtifactId());
            }
            DependencyNode parent = parentOf.get(node);
            if (parent != null) {
                queue.add(parent);
            }
        }
        return consumers;
    }

    private void buildParentMap(DependencyNode node, DependencyNode parent,
                                Map<DependencyNode, DependencyNode> map, Set<DependencyNode> seen) {
        // Aether reuses node instances for shared dependencies, so an unguarded walk can loop.
        if (!seen.add(node)) {
            return;
        }
        map.putIfAbsent(node, parent);
        for (DependencyNode child : node.getChildren()) {
            buildParentMap(child, node, map, seen);
        }
    }

    private void collectNodesByGA(DependencyNode node, String targetGA, List<DependencyNode> out,
                                  Set<DependencyNode> seen) {
        if (!seen.add(node)) {
            return;
        }
        Artifact artifact = node.getArtifact();
        if (artifact != null && (artifact.getGroupId() + ":" + artifact.getArtifactId()).equals(targetGA)) {
            out.add(node);
        }
        for (DependencyNode child : node.getChildren()) {
            collectNodesByGA(child, targetGA, out, seen);
        }
    }
}
