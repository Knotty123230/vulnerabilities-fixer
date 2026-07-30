package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.repository.RemoteRepository;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

/**
 * Turns a scanner's vulnerability list into verified POM edits.
 *
 * <p>The contract is that nothing is written unless it has been proven to work. For each
 * vulnerable component the engine builds a list of candidate edits, resolves the dependency graph
 * that each candidate would produce, and keeps only an edit that actually removes the affected
 * version. A "fix" that merely changes a version number without changing what Maven resolves is
 * worse than no fix at all, because it looks like remediation in a diff.
 */
public class RemediationEngine {

    /** Knobs the CLI exposes. */
    public record Options(
            VersionPolicy.UpgradeScope upgradeScope,
            boolean dryRun,
            boolean checkLinkage,
            int maxAttemptsPerStrategy,
            boolean alignFamilies
    ) {
        public static Options defaults() {
            return new Options(VersionPolicy.UpgradeScope.MINOR, false, false, 12, false);
        }
    }

    /**
     * Version groups that must move together: mixing versions inside them produces the very
     * linkage errors this tool is meant to prevent (e.g. a logback-classic that expects a newer
     * logback-core). Upgrading them with a wildcard artifactId keeps the set consistent.
     */
    private static final Set<String> LOCKSTEP_GROUPS = Set.of(
            "ch.qos.logback",
            "org.slf4j",
            "com.fasterxml.jackson.core",
            "com.fasterxml.jackson.datatype",
            "org.springframework",
            "io.netty");

    private final SonatypeScanReport report;
    private final LocalProjectAnalyzer analyzer;
    private final VersionCatalog versionCatalog;
    private final MavenPomFixer pomFixer;
    private final LinkageAnalyzer linkageAnalyzer;
    private final BomLocator bomLocator;
    private final VersionSkewDetector skewDetector;
    private final Path projectPath;
    private final Options options;

    public RemediationEngine(SonatypeScanReport report,
                             RepositorySystem repositorySystem,
                             RepositorySystemSession session,
                             List<RemoteRepository> repositories,
                             NexusCredentials credentials,
                             Path projectPath,
                             Options options) {
        this.report = report;
        this.projectPath = projectPath;
        this.options = options;
        this.analyzer = new LocalProjectAnalyzer(repositorySystem, session, repositories);
        this.versionCatalog = new VersionCatalog(repositorySystem, session, repositories);
        this.pomFixer = new MavenPomFixer(credentials);
        this.linkageAnalyzer = new LinkageAnalyzer(analyzer, projectPath);
        this.bomLocator = new BomLocator(repositorySystem, session, repositories, versionCatalog);
        this.skewDetector = new VersionSkewDetector(bomLocator);
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    public ScanReport run(File pomFile) throws Exception {
        Instant startedAt = Instant.now();

        Log.section("Resolving dependency graph");
        DependencyNode graph = analyzer.buildGraphFromPom(pomFile);
        Log.step("Resolved %d direct dependencies", graph.getChildren().size());

        List<ScanReport.Finding> findings = new ArrayList<>();
        List<SonatypeScanReport.VulnerabilityDetails> vulnerabilities = report.vulnerabilities();

        Log.section(String.format("Remediating %d vulnerable component(s)", vulnerabilities.size()));

        for (int i = 0; i < vulnerabilities.size(); i++) {
            SonatypeScanReport.VulnerabilityDetails vulnerability = vulnerabilities.get(i);
            Vulnerability parsed = parsePackageUrl(vulnerability);
            if (parsed == null) {
                Log.debug("Skipping component with unparseable packageUrl: %s", vulnerability.packageUrl());
                continue;
            }

            try {
                ScanReport.Finding finding = remediate(pomFile, graph, vulnerability, parsed);
                findings.add(finding);
                Log.step("[%d/%d] %-45s %s", i + 1, vulnerabilities.size(),
                        parsed.coordinate(), progressLabel(finding));
                // A written change invalidates the graph everything else was reasoned against.
                if (finding.outcome() == ScanReport.Outcome.FIXED) {
                    analyzer.invalidate(pomFile);
                    graph = analyzer.buildGraphFromPom(pomFile);
                }
            } catch (Exception e) {
                Log.debug("Remediation of %s failed: %s", parsed.coordinate(), Log.describe(e));
                findings.add(errorFinding(parsed, vulnerability, Log.describe(e)));
                Log.step("[%d/%d] %-45s %s", i + 1, vulnerabilities.size(),
                        parsed.coordinate(), Log.red("error"));
            }
        }

        // Skew is assessed on the final graph, so a family that the fixes happened to align
        // is not reported as an outstanding problem.
        Log.section("Checking for version skew");
        List<ScanReport.FamilySkew> skews = detectSkew(graph);
        Log.step(skews.isEmpty()
                ? "No mixed-version artifact families found."
                : skews.size() + " artifact family/families resolve at mixed versions.");

        return new ScanReport(
                projectPath.toAbsolutePath().normalize().toString(),
                report.applicationId(),
                report.reportUrl(),
                startedAt,
                Duration.between(startedAt, Instant.now()).toMillis(),
                options.dryRun(),
                options.upgradeScope().describe(),
                report.totalComponents(),
                List.copyOf(findings),
                skews);
    }

    /**
     * Reports mixed-version families. Detection always runs — knowing a family has drifted is
     * useful whether or not the tool is allowed to restructure the POM to fix it.
     */
    private List<ScanReport.FamilySkew> detectSkew(DependencyNode graph) {
        try {
            return skewDetector.detect(graph).stream()
                    .map(skew -> new ScanReport.FamilySkew(
                            skew.groupId(),
                            skew.distinctVersions(),
                            skew.resolvedArtifacts(),
                            skew.bomCoordinate(),
                            skew.bom() == null ? null : skew.bom().version(),
                            false))
                    .toList();
        } catch (Exception e) {
            Log.debug("Version-skew detection failed: %s", Log.describe(e));
            return List.of();
        }
    }

    /** One-glance status for the progress line, so a long run is never silently opaque. */
    private static String progressLabel(ScanReport.Finding finding) {
        return switch (finding.outcome()) {
            case FIXED -> Log.green("fixed") + "  " + Log.dim(finding.appliedChange());
            case WOULD_FIX -> Log.cyan("would fix") + "  " + Log.dim(finding.appliedChange());
            case NOT_AFFECTED -> Log.dim("not affected (resolves " + finding.resolvedVersion() + ")");
            case NOT_IN_GRAPH -> Log.dim("not in this module");
            case NO_REMEDIATION_AVAILABLE -> Log.yellow("no fix published");
            case REJECTED_BREAKS_COMPATIBILITY -> Log.red("rejected: breaks compatibility");
            case NO_WORKING_FIX -> Log.red("no working fix");
            case ERROR -> Log.red("error");
        };
    }

    // ------------------------------------------------------------------
    // Per-component remediation
    // ------------------------------------------------------------------

    private ScanReport.Finding remediate(File pomFile,
                                         DependencyNode graph,
                                         SonatypeScanReport.VulnerabilityDetails details,
                                         Vulnerability vulnerability) throws Exception {

        FindingBuilder builder = new FindingBuilder(vulnerability, details);

        List<LocalProjectAnalyzer.GraphPath> paths =
                analyzer.findPathsTo(graph, vulnerability.groupId(), vulnerability.artifactId());
        if (paths.isEmpty()) {
            Log.debug("%s is absent from the resolved graph", vulnerability.coordinate());
            return builder.outcome(ScanReport.Outcome.NOT_IN_GRAPH).build();
        }
        builder.paths(paths);

        String resolvedVersion = paths.getFirst().target().getVersion();
        builder.resolvedVersion(resolvedVersion);

        // The scanner reports what the last scan saw; the POM may have moved on since,
        // and dependencyManagement may already pin a safe version.
        if (!VersionPolicy.isStillAffected(resolvedVersion, vulnerability.version(), vulnerability.versionToFix())) {
            Log.debug("%s resolves to %s, which is not affected", vulnerability.coordinate(), resolvedVersion);
            return builder.outcome(ScanReport.Outcome.NOT_AFFECTED)
                    .note("Maven resolves " + resolvedVersion + ", which is at or beyond a fixed version")
                    .build();
        }

        if (vulnerability.versionToFix().isEmpty()) {
            return builder.outcome(ScanReport.Outcome.NO_REMEDIATION_AVAILABLE)
                    .note("the scanner did not publish a remediated version for this advisory")
                    .build();
        }

        if (options.checkLinkage()) {
            linkageAnalyzer.establishBaseline(graph, vulnerability.groupId(), vulnerability.artifactId());
        }

        List<Strategy> strategies = buildStrategies(pomFile, graph, paths, vulnerability, resolvedVersion);
        builder.controlPoint(strategies.isEmpty() ? "none found" : strategies.getFirst().name());

        Set<String> attempted = new LinkedHashSet<>();
        for (Strategy strategy : strategies) {
            if (strategy.candidates().isEmpty()) {
                Log.debug("Strategy '%s' has no candidate versions within policy", strategy.name());
                continue;
            }
            attempted.addAll(strategy.candidates());
            Log.debug("Trying strategy '%s' with %d candidate(s)", strategy.name(), strategy.candidates().size());

            Optional<Applied> applied = attemptStrategy(pomFile, strategy, vulnerability);
            if (applied.isPresent()) {
                return finishSuccessfully(pomFile, builder, strategy, applied.get());
            }
            if (strategy.rejectedForCompatibility) {
                builder.linkageWarnings(strategy.linkageWarnings);
            }
        }

        builder.candidates(List.copyOf(attempted));
        boolean anyCompatibilityRejection = strategies.stream().anyMatch(s -> s.rejectedForCompatibility);
        if (anyCompatibilityRejection) {
            return builder.outcome(ScanReport.Outcome.REJECTED_BREAKS_COMPATIBILITY)
                    .note("an upgrade removes the vulnerable version but breaks binary compatibility")
                    .build();
        }
        if (attempted.isEmpty()) {
            return builder.outcome(ScanReport.Outcome.NO_WORKING_FIX)
                    .note("no upgrade candidate exists within the "
                            + options.upgradeScope().describe() + " policy; try --upgrade-scope major")
                    .build();
        }
        return builder.outcome(ScanReport.Outcome.NO_WORKING_FIX)
                .note("none of the " + attempted.size()
                        + " candidate version(s) removed the affected version from the resolved graph")
                .build();
    }

    private ScanReport.Finding finishSuccessfully(File pomFile, FindingBuilder builder,
                                                  Strategy strategy, Applied applied) throws Exception {
        builder.change(strategy.describeChange(applied.version()), strategy.editedCoordinate(), applied.version())
                .controlPoint(strategy.name())
                .linkageWarnings(strategy.linkageWarnings);

        if (options.dryRun()) {
            return builder.outcome(ScanReport.Outcome.WOULD_FIX).build();
        }

        pomFixer.write(pomFile, applied.pomContent());
        analyzer.invalidate(pomFile);
        return builder.outcome(ScanReport.Outcome.FIXED).build();
    }

    // ------------------------------------------------------------------
    // Strategies
    // ------------------------------------------------------------------

    /** One way of moving a version, plus the versions worth trying for it. */
    private final class Strategy {
        private final String name;
        private final String editedCoordinate;
        private final String currentVersion;
        private final List<String> candidates;
        private final Function<String, String> preview;

        private boolean rejectedForCompatibility;
        private List<String> linkageWarnings = List.of();

        Strategy(String name, String editedCoordinate, String currentVersion, List<String> candidates,
                 Function<String, String> preview) {
            this.name = name;
            this.editedCoordinate = editedCoordinate;
            this.currentVersion = currentVersion;
            this.candidates = candidates;
            this.preview = preview;
        }

        String name() {
            return name;
        }

        String editedCoordinate() {
            return editedCoordinate;
        }

        List<String> candidates() {
            return candidates;
        }

        /** e.g. {@code org.apache.commons:commons-configuration2 2.7 -> 2.9.0 (minor)}. */
        String describeChange(String version) {
            return editedCoordinate + " " + VersionPolicy.describeJump(currentVersion, version);
        }
    }

    /**
     * Builds the ordered list of ways to fix this vulnerability.
     *
     * <p>Order is least-invasive first, so the resulting diff is the one a reviewer would have
     * written by hand: bump the thing that is actually declared, then the BOM or parent that
     * governs it, and only as a last resort pin the transitive artifact in
     * {@code dependencyManagement}. The pin always works — Maven gives the current POM's
     * {@code dependencyManagement} precedence over both mediation and imported BOMs — which is
     * exactly why it must not be the first answer: it silently diverges the project from its BOM.
     */
    private List<Strategy> buildStrategies(File pomFile,
                                           DependencyNode graph,
                                           List<LocalProjectAnalyzer.GraphPath> paths,
                                           Vulnerability vulnerability,
                                           String resolvedVersion) throws Exception {
        List<Strategy> strategies = new ArrayList<>();
        Artifact directDependency = paths.getFirst().directDependency();
        boolean vulnerableIsDirect = paths.getFirst().isDirect();

        // When the vulnerable artifact belongs to a family that has already drifted apart,
        // importing its BOM is the correct fix rather than a heavier alternative: it clears the
        // vulnerability and removes the skew that would otherwise cause the next one.
        addFamilyAlignmentStrategy(pomFile, strategies, graph, vulnerability, resolvedVersion);

        LocalProjectAnalyzer.UpdateStrategy controlPoint = analyzer.determineUpdateStrategy(
                pomFile, directDependency.getGroupId(), directDependency.getArtifactId());
        Log.debug("Control point for %s:%s is %s",
                directDependency.getGroupId(), directDependency.getArtifactId(), controlPoint);

        // 1. The vulnerable artifact is itself declared here — move it straight to a fixed version.
        if (vulnerableIsDirect) {
            List<String> fixVersions = VersionPolicy.candidates(
                    vulnerability.versionToFix(), resolvedVersion, options.upgradeScope());
            Artifact target = lockstepAware(new DefaultArtifact(
                    vulnerability.groupId(), vulnerability.artifactId(), "jar", resolvedVersion));
            strategies.add(new Strategy("direct dependency", coordinateOf(target), resolvedVersion, fixVersions,
                    version -> pomFixer.previewUpgrade(pomFile, target, version)));
        }

        // 2. Bump the declared dependency that drags the vulnerable one in.
        if (!vulnerableIsDirect && controlPoint != LocalProjectAnalyzer.UpdateStrategy.TRANSITIVE_ONLY) {
            List<String> candidates = versionCatalog.upgradeCandidates(
                    directDependency.getGroupId(), directDependency.getArtifactId(),
                    directDependency.getExtension(), directDependency.getVersion(), options.upgradeScope());
            Artifact target = lockstepAware(directDependency);
            strategies.add(new Strategy("declared dependency", coordinateOf(target), directDependency.getVersion(),
                    cap(candidates), version -> pomFixer.previewUpgrade(pomFile, target, version)));
        }

        // 3. Whatever governs the version: an imported BOM, or the parent POM.
        if (controlPoint == LocalProjectAnalyzer.UpdateStrategy.MANAGED_BY_BOM) {
            addBomStrategy(pomFile, strategies, directDependency, vulnerability);
        }
        if (controlPoint == LocalProjectAnalyzer.UpdateStrategy.MANAGED_BY_PARENT
                || controlPoint == LocalProjectAnalyzer.UpdateStrategy.MANAGED_BY_BOM
                || controlPoint == LocalProjectAnalyzer.UpdateStrategy.TRANSITIVE_ONLY) {
            addParentStrategy(pomFile, strategies);
        }

        // 4. Last resort: pin the vulnerable artifact in dependencyManagement.
        List<String> pinVersions = VersionPolicy.candidates(
                vulnerability.versionToFix(), resolvedVersion, options.upgradeScope());
        strategies.add(new Strategy("dependencyManagement pin", vulnerability.coordinate(), resolvedVersion,
                pinVersions,
                version -> pomFixer.previewManagedOverride(
                        pomFile, vulnerability.groupId(), vulnerability.artifactId(), version)));

        return strategies;
    }

    /**
     * Adds the "import the family BOM" strategy, when {@code --align-families} is on and the
     * vulnerable artifact's family has actually drifted.
     *
     * <p>Deliberately conditional on observed skew. Importing a BOM into a POM whose family is
     * already consistent buys nothing and carries real cost: the import lands in the current POM's
     * {@code dependencyManagement}, which outranks any inherited BOM, so it quietly detaches the
     * project from — say — the Spring Boot BOM that was managing that family perfectly well.
     */
    private void addFamilyAlignmentStrategy(File pomFile, List<Strategy> strategies, DependencyNode graph,
                                            Vulnerability vulnerability, String resolvedVersion) {
        if (!options.alignFamilies()) {
            return;
        }
        Optional<VersionSkewDetector.Skew> skew = skewDetector.detect(graph).stream()
                .filter(candidate -> candidate.groupId().equals(vulnerability.groupId()))
                .findFirst();
        if (skew.isEmpty()) {
            return;
        }

        BomLocator.Bom bom = skew.get().bom();
        // Two constraints on the floor. The family must not be moved backwards, so it is at least
        // the highest version any member already resolves to; and the import has to clear the
        // vulnerability, so it is also at least the lowest remediated version. Starting the search
        // here means the smallest candidate is already a valid answer, and the binary search below
        // converges on the minimal bump rather than an arbitrary later one.
        String floor = highestOf(skew.get().highestVersion(), lowestRemediation(vulnerability));
        List<String> candidates = bomLocator.upgradeCandidates(bom, floor, options.upgradeScope());
        if (candidates.isEmpty()) {
            Log.debug("No %s version at or above %s within policy", bom.coordinate(), floor);
            return;
        }

        Log.debug("Family %s is skewed %s; trying BOM %s",
                skew.get().groupId(), skew.get().distinctVersions(), bom.coordinate());

        // Displayed as a move from where the family actually sits today, not from the computed
        // search floor — "4.1.110.Final -> 4.1.118.Final" is the change a reviewer sees.
        strategies.addFirst(new Strategy("family BOM import", bom.coordinate(),
                skew.get().highestVersion(), cap(candidates),
                version -> pomFixer.previewBomImport(
                        pomFile, bom.groupId(), bom.artifactId(), version, vulnerability.groupId())));
    }

    /** The lowest version the scanner considers remediated, or {@code null} when it offers none. */
    private static String lowestRemediation(Vulnerability vulnerability) {
        return vulnerability.versionToFix().isEmpty() ? null : vulnerability.versionToFix().getFirst();
    }

    private static String highestOf(String left, String right) {
        if (left == null) {
            return right;
        }
        if (right == null) {
            return left;
        }
        return VersionPolicy.compare(left, right) >= 0 ? left : right;
    }

    private void addBomStrategy(File pomFile, List<Strategy> strategies,
                                Artifact directDependency, Vulnerability vulnerability) throws Exception {
        org.apache.maven.model.Dependency bom = analyzer.findBomManagingDependency(pomFile, directDependency);
        if (bom == null) {
            // The BOM may manage the vulnerable artifact without managing its consumer.
            bom = analyzer.findBomManagingDependency(pomFile, new DefaultArtifact(
                    vulnerability.groupId(), vulnerability.artifactId(), "jar", vulnerability.version()));
        }
        if (bom == null) {
            Log.debug("No imported BOM manages %s", vulnerability.coordinate());
            return;
        }
        Artifact bomArtifact = new DefaultArtifact(bom.getGroupId(), bom.getArtifactId(), "pom", bom.getVersion());
        List<String> candidates = versionCatalog.upgradeCandidates(
                bom.getGroupId(), bom.getArtifactId(), "pom", bom.getVersion(), options.upgradeScope());
        strategies.add(new Strategy("imported BOM", coordinateOf(bomArtifact), bom.getVersion(), cap(candidates),
                version -> pomFixer.previewUpgrade(pomFile, bomArtifact, version)));
    }

    private void addParentStrategy(File pomFile, List<Strategy> strategies) throws Exception {
        Artifact parent = analyzer.getParentCandidate(pomFile);
        if (parent == null) {
            return;
        }
        List<String> candidates = versionCatalog.upgradeCandidates(
                parent.getGroupId(), parent.getArtifactId(), "pom", parent.getVersion(), options.upgradeScope());
        strategies.add(new Strategy("parent POM", coordinateOf(parent), parent.getVersion(), cap(candidates),
                version -> pomFixer.previewUpgrade(pomFile, parent, version)));
    }

    /**
     * For groups that ship as a coordinated set, targets every artifact of the group with a
     * wildcard so the whole set moves together.
     */
    private static Artifact lockstepAware(Artifact artifact) {
        if (!LOCKSTEP_GROUPS.contains(artifact.getGroupId())) {
            return artifact;
        }
        return new DefaultArtifact(artifact.getGroupId(), "*", artifact.getExtension(), artifact.getVersion());
    }

    private static String coordinateOf(Artifact artifact) {
        return artifact.getGroupId() + ":" + artifact.getArtifactId();
    }

    /**
     * Bounds how many versions of one artifact a run will resolve graphs for, by sampling the
     * candidate range evenly.
     *
     * <p>Keeping only the newest N looks reasonable and is not: the search below hunts for the
     * <em>smallest</em> sufficient bump, so discarding the low end guarantees it cannot find one.
     * A busy project like Netty publishes dozens of patches between two minors, and truncating to
     * the tail turned a one-patch fix into a minor-version jump.
     *
     * <p>Even sampling keeps the first and last candidate and spreads the rest, so the result is
     * at worst one sampling step above the true minimum instead of arbitrarily far above it.
     */
    private List<String> cap(List<String> candidates) {
        int limit = options.maxAttemptsPerStrategy();
        if (candidates.size() <= limit) {
            return candidates;
        }
        if (limit == 1) {
            return List.of(candidates.getLast());
        }

        List<String> sampled = new ArrayList<>(limit);
        // Distribute limit picks across [0, size-1] inclusive of both ends.
        for (int i = 0; i < limit; i++) {
            int index = (int) Math.round((double) i * (candidates.size() - 1) / (limit - 1));
            String candidate = candidates.get(index);
            if (sampled.isEmpty() || !sampled.getLast().equals(candidate)) {
                sampled.add(candidate);
            }
        }
        return List.copyOf(sampled);
    }

    // ------------------------------------------------------------------
    // Candidate verification
    // ------------------------------------------------------------------

    private record Applied(String version, String pomContent) {
    }

    /**
     * Finds the smallest candidate version that actually clears the vulnerability.
     *
     * <p>Candidates are ascending, and verification requires resolving a full dependency graph
     * per attempt, so a linear walk is the expensive part of a run. Instead the newest candidate
     * is tried first: if even that fails, the strategy cannot work and the rest are skipped
     * outright. If it succeeds, a binary search finds the smallest version that also works —
     * {@code log2(n)} graph resolutions instead of {@code n}, and the smallest sufficient bump
     * rather than the largest.
     *
     * <p>This assumes remediation is monotonic: if version X is fixed, later versions are too.
     * That holds for the "upgrade past the fix" model every advisory feed uses; a regression
     * that re-introduces a CVE under the same identifier would defeat it, and would also defeat
     * the scanner that reported it.
     */
    private Optional<Applied> attemptStrategy(File pomFile, Strategy strategy, Vulnerability vulnerability) {
        List<String> candidates = strategy.candidates();

        Applied newest = verifyCandidate(pomFile, strategy, vulnerability, candidates.getLast());
        if (newest == null) {
            return Optional.empty();
        }

        int low = 0;
        int high = candidates.size() - 1;
        Applied best = newest;
        while (low < high) {
            int mid = (low + high) / 2;
            Applied result = verifyCandidate(pomFile, strategy, vulnerability, candidates.get(mid));
            if (result != null) {
                best = result;
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        return Optional.of(best);
    }

    /**
     * Applies one candidate to a scratch POM, resolves it, and reports whether the result is
     * both free of the vulnerability and binary-compatible.
     */
    private Applied verifyCandidate(File pomFile, Strategy strategy, Vulnerability vulnerability, String version) {
        String pomContent = strategy.preview.apply(version);
        if (pomContent == null) {
            Log.debug("  %s @ %s: recipe produced no change", strategy.name(), version);
            return null;
        }

        // The scratch POM lives beside the real one so that <parent><relativePath>, properties
        // and sibling modules resolve exactly as they would for the real file. A temp directory
        // would quietly change the answer.
        Path scratch = projectPath.resolve(".vulnchecker-verify.pom.xml");
        try {
            Files.writeString(scratch, pomContent);
            DependencyNode candidateGraph = analyzer.buildGraphFromPom(scratch.toFile());

            String resolved = analyzer.resolvedVersionOf(
                    candidateGraph, vulnerability.groupId(), vulnerability.artifactId());
            if (resolved == null) {
                Log.debug("  %s @ %s: vulnerable artifact no longer in graph", strategy.name(), version);
                return new Applied(version, pomContent);
            }
            if (VersionPolicy.isStillAffected(resolved, vulnerability.version(), vulnerability.versionToFix())) {
                Log.debug("  %s @ %s: still resolves %s", strategy.name(), version, resolved);
                return null;
            }

            if (options.checkLinkage()) {
                LinkageAnalyzer.Verdict verdict = linkageAnalyzer.verify(
                        candidateGraph, vulnerability.groupId(), vulnerability.artifactId());
                if (verdict.wasSkipped()) {
                    strategy.linkageWarnings = List.of("binary-compatibility check skipped: " + verdict.skipReason());
                } else if (!verdict.compatible()) {
                    Log.debug("  %s @ %s: %d linkage regression(s)",
                            strategy.name(), version, verdict.regressions().size());
                    strategy.rejectedForCompatibility = true;
                    strategy.linkageWarnings = verdict.renderRegressions(5);
                    return null;
                }
            }

            Log.debug("  %s @ %s: verified (%s -> %s)",
                    strategy.name(), version, vulnerability.version(), resolved);
            return new Applied(version, pomContent);

        } catch (Exception e) {
            Log.debug("  %s @ %s: candidate POM does not resolve: %s", strategy.name(), version, Log.describe(e));
            return null;
        } finally {
            try {
                Files.deleteIfExists(scratch);
            } catch (Exception cleanupFailure) {
                Log.debug("Could not remove scratch POM %s: %s", scratch, cleanupFailure.getMessage());
            }
        }
    }

    // ------------------------------------------------------------------
    // Parsing and report assembly
    // ------------------------------------------------------------------

    /**
     * Parses a Maven package URL, e.g.
     * {@code pkg:maven/ch.qos.logback/logback-core@1.4.11?type=jar}.
     */
    static Vulnerability parsePackageUrl(SonatypeScanReport.VulnerabilityDetails details) {
        String packageUrl = details.packageUrl();
        if (packageUrl == null || !packageUrl.startsWith("pkg:maven/")) {
            return null;
        }
        String remainder = packageUrl.substring("pkg:maven/".length());

        int qualifierIndex = remainder.indexOf('?');
        if (qualifierIndex >= 0) {
            remainder = remainder.substring(0, qualifierIndex);
        }
        int versionIndex = remainder.lastIndexOf('@');
        if (versionIndex < 0) {
            return null;
        }
        String coordinate = remainder.substring(0, versionIndex);
        String version = remainder.substring(versionIndex + 1);

        int separator = coordinate.lastIndexOf('/');
        if (separator < 0) {
            return null;
        }

        List<String> fixVersions = details.remediationVersions().stream()
                .map(SonatypeScanReport.RemediationVersion::version)
                .filter(v -> v != null && !v.isBlank())
                .distinct()
                .sorted(VersionPolicy.ascending())
                .toList();

        return new Vulnerability(
                coordinate.substring(0, separator),
                coordinate.substring(separator + 1),
                version,
                fixVersions);
    }

    private ScanReport.Finding errorFinding(Vulnerability vulnerability,
                                            SonatypeScanReport.VulnerabilityDetails details, String message) {
        return new FindingBuilder(vulnerability, details)
                .outcome(ScanReport.Outcome.ERROR)
                .note(message)
                .build();
    }

    /** Accumulates the per-component facts that end up in the report. */
    private static final class FindingBuilder {
        private final Vulnerability vulnerability;
        private final SonatypeScanReport.VulnerabilityDetails details;
        private final List<String> notes = new ArrayList<>();

        private String resolvedVersion;
        private List<LocalProjectAnalyzer.GraphPath> paths = List.of();
        private String controlPoint;
        private List<String> candidates = List.of();
        private ScanReport.Outcome outcome = ScanReport.Outcome.ERROR;
        private String appliedChange;
        private String editedCoordinate;
        private String toVersion;
        private List<String> linkageWarnings = List.of();

        FindingBuilder(Vulnerability vulnerability, SonatypeScanReport.VulnerabilityDetails details) {
            this.vulnerability = vulnerability;
            this.details = details;
        }

        FindingBuilder resolvedVersion(String value) {
            this.resolvedVersion = value;
            return this;
        }

        FindingBuilder paths(List<LocalProjectAnalyzer.GraphPath> value) {
            this.paths = value;
            return this;
        }

        FindingBuilder controlPoint(String value) {
            this.controlPoint = value;
            return this;
        }

        FindingBuilder candidates(List<String> value) {
            this.candidates = value;
            return this;
        }

        FindingBuilder outcome(ScanReport.Outcome value) {
            this.outcome = value;
            return this;
        }

        FindingBuilder note(String value) {
            this.notes.add(value);
            return this;
        }

        FindingBuilder linkageWarnings(List<String> value) {
            this.linkageWarnings = value;
            return this;
        }

        FindingBuilder change(String description, String coordinate, String version) {
            this.appliedChange = description;
            this.editedCoordinate = coordinate;
            this.toVersion = version;
            return this;
        }

        ScanReport.Finding build() {
            List<ScanReport.Issue> issues = details.securityIssues().stream()
                    .map(issue -> new ScanReport.Issue(
                            issue.reference(), issue.severity(), issue.url(), issue.reason()))
                    .toList();

            int severityRank = issues.stream()
                    .mapToInt(issue -> VersionPolicy.severityRank(issue.severity()))
                    .max()
                    .orElse(0);

            return new ScanReport.Finding(
                    vulnerability.groupId(),
                    vulnerability.artifactId(),
                    vulnerability.version(),
                    resolvedVersion,
                    severityRank,
                    VersionPolicy.severityLabel(severityRank),
                    issues,
                    details.directDependency() || paths.stream().anyMatch(LocalProjectAnalyzer.GraphPath::isDirect),
                    paths.isEmpty() ? null : paths.getFirst().render(),
                    paths.stream().map(LocalProjectAnalyzer.GraphPath::render).toList(),
                    controlPoint,
                    candidates,
                    outcome,
                    appliedChange,
                    editedCoordinate,
                    resolvedVersion != null ? resolvedVersion : vulnerability.version(),
                    toVersion,
                    linkageWarnings,
                    List.copyOf(notes));
        }
    }
}
