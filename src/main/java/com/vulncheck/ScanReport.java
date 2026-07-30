package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The result of one run, in a form that is equally usable by a human reading a terminal,
 * a Markdown comment on a merge request, and a CI gate reading JSON.
 *
 * <p>This is the single source of truth for what happened: nothing meaningful is only ever
 * printed. Renderers project this record, they never re-derive facts.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ScanReport(
        String projectPath,
        String applicationId,
        String sonatypeReportUrl,
        Instant startedAt,
        long durationMillis,
        boolean dryRun,
        String upgradeScope,
        int componentsScanned,
        List<Finding> findings
) {

    /** What the tool managed to do about one vulnerable component. */
    public enum Outcome {
        /** A version change was found and verified (and written, unless {@code --dry-run}). */
        FIXED,
        /** A verified fix exists but was not written because this was a dry run. */
        WOULD_FIX,
        /** The scanner flagged it, but the resolved graph does not contain an affected version. */
        NOT_AFFECTED,
        /** The component is not reachable from this POM at all (other module, or stale report). */
        NOT_IN_GRAPH,
        /** The scanner offered no remediation version. */
        NO_REMEDIATION_AVAILABLE,
        /** Candidate versions existed, but none produced a graph that clears the vulnerability. */
        NO_WORKING_FIX,
        /** A fix cleared the vulnerability but broke binary compatibility. */
        REJECTED_BREAKS_COMPATIBILITY,
        /** The attempt failed for a technical reason (network, unparseable POM, ...). */
        ERROR;

        public boolean isResolved() {
            return this == FIXED || this == WOULD_FIX || this == NOT_AFFECTED;
        }

        /** Whether this outcome represents an unmitigated risk that a CI gate should weigh. */
        public boolean isOutstanding() {
            return this == NO_WORKING_FIX
                    || this == NO_REMEDIATION_AVAILABLE
                    || this == REJECTED_BREAKS_COMPATIBILITY
                    || this == ERROR;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Finding(
            String groupId,
            String artifactId,
            String vulnerableVersion,
            String resolvedVersion,
            int severityRank,
            String severity,
            List<Issue> issues,
            boolean directDependency,
            String dependencyPath,
            List<String> allDependencyPaths,
            String controlPoint,
            List<String> candidateVersions,
            Outcome outcome,
            String appliedChange,
            String editedCoordinate,
            String fromVersion,
            String toVersion,
            List<String> linkageWarnings,
            List<String> notes
    ) {
        public String coordinate() {
            return groupId + ":" + artifactId;
        }

        public String gav() {
            return coordinate() + ":" + vulnerableVersion;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Issue(String reference, String severity, String url, String reason) {
    }

    // ------------------------------------------------------------------
    // Derived views
    // ------------------------------------------------------------------

    public Duration duration() {
        return Duration.ofMillis(durationMillis);
    }

    public Map<Outcome, Long> outcomeCounts() {
        return findings.stream().collect(Collectors.groupingBy(Finding::outcome, Collectors.counting()));
    }

    public List<Finding> fixed() {
        return findings.stream()
                .filter(f -> f.outcome() == Outcome.FIXED || f.outcome() == Outcome.WOULD_FIX)
                .toList();
    }

    /** Findings a CI gate should consider, worst first. */
    public List<Finding> outstanding() {
        return findings.stream()
                .filter(f -> f.outcome().isOutstanding())
                .sorted(Comparator.comparingInt(Finding::severityRank).reversed()
                        .thenComparing(Finding::coordinate))
                .toList();
    }

    /** Highest severity among findings that are still outstanding; 0 when there are none. */
    public int highestOutstandingSeverity() {
        return outstanding().stream().mapToInt(Finding::severityRank).max().orElse(0);
    }

    public boolean anyChangesWritten() {
        return findings.stream().anyMatch(f -> f.outcome() == Outcome.FIXED);
    }
}
