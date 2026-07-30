package com.vulncheck;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Renders a {@link ScanReport} for a terminal or a CI job log.
 *
 * <p>The guiding constraint is that someone skimming a failed pipeline should learn, in the
 * first five lines, whether they are blocked and by what. Detail is grouped underneath, and
 * dependency paths — the thing people actually need to act on a transitive CVE — are always
 * shown for outstanding findings.
 */
public final class ConsoleReportRenderer {

    private ConsoleReportRenderer() {
    }

    public static void render(ScanReport report) {
        renderHeader(report);
        renderGroup("RESOLVED", report.findings().stream().filter(f -> f.outcome().isResolved()).toList(), true);
        renderGroup("OUTSTANDING", report.outstanding(), false);
        renderInformational(report);
        renderFamilySkew(report);
        renderSummary(report);
    }

    /**
     * Mixed-version artifact families. Reported separately from vulnerabilities because it is a
     * different kind of defect — a latent {@code NoSuchMethodError} rather than a known CVE.
     */
    private static void renderFamilySkew(ScanReport report) {
        List<ScanReport.FamilySkew> skews = report.familySkews();
        if (skews == null || skews.isEmpty()) {
            return;
        }
        Log.report("");
        Log.report(Log.yellow(Log.bold("MIXED VERSIONS (" + skews.size() + ")")));
        Log.report(Log.dim("  These artifacts ship as a set but resolved at different versions."));

        for (ScanReport.FamilySkew skew : skews) {
            Log.report("  %s %s %s",
                    Log.yellow("!"),
                    Log.bold(skew.groupId()),
                    Log.dim(String.join(", ", skew.versions())));

            skew.resolvedArtifacts().entrySet().stream()
                    .sorted(java.util.Map.Entry.comparingByKey())
                    .limit(Log.isVerbose() ? Integer.MAX_VALUE : 6)
                    .forEach(entry -> Log.report("      %s %s:%s",
                            Log.dim("   "), entry.getKey(), entry.getValue()));

            if (skew.bomCoordinate() != null) {
                Log.report("      %s import %s:%s to pin the whole family",
                        Log.cyan("fix"), skew.bomCoordinate(), skew.suggestedBomVersion());
                Log.report("      %s %s", Log.dim("   "), Log.dim("re-run with --align-families to apply"));
            }
        }
    }

    private static void renderHeader(ScanReport report) {
        Log.report("");
        Log.report(Log.bold("Dependency vulnerability report"));
        Log.report(Log.dim("─".repeat(64)));
        field("Project", report.projectPath());
        if (report.applicationId() != null) {
            field("Application", report.applicationId());
        }
        if (report.sonatypeReportUrl() != null) {
            field("Scan report", report.sonatypeReportUrl());
        }
        field("Components", report.componentsScanned() + " scanned, " + report.findings().size() + " vulnerable");
        field("Policy", report.upgradeScope() + (report.dryRun() ? Log.yellow(" · dry-run (no files written)") : ""));
        field("Duration", humanDuration(report.duration()));
    }

    private static void field(String label, String value) {
        Log.report("%-12s %s", label, value);
    }

    private static void renderGroup(String title, List<ScanReport.Finding> findings, boolean resolved) {
        if (findings.isEmpty()) {
            return;
        }
        Log.report("");
        String heading = title + " (" + findings.size() + ")";
        Log.report(resolved ? Log.green(Log.bold(heading)) : Log.red(Log.bold(heading)));

        for (ScanReport.Finding finding : findings) {
            renderFinding(finding, resolved);
        }
    }

    private static void renderFinding(ScanReport.Finding finding, boolean resolved) {
        String marker = resolved ? Log.green("✔") : Log.red("✖");
        String severity = severityBadge(finding.severityRank());

        Log.report("  %s %s %s %s",
                marker,
                Log.bold(finding.coordinate()),
                Log.dim(finding.vulnerableVersion()),
                severity);

        if (finding.appliedChange() != null) {
            Log.report("      %s %s", Log.cyan("fix"), finding.appliedChange());
        }

        String issues = summariseIssues(finding);
        if (issues != null) {
            Log.report("      %s %s", Log.dim("cve"), issues);
        }

        if (finding.dependencyPath() != null && !finding.directDependency()) {
            Log.report("      %s %s", Log.dim("via"), finding.dependencyPath());
        }

        // Extra routes explain why a single edit may not have been enough.
        if (finding.allDependencyPaths() != null && finding.allDependencyPaths().size() > 1) {
            int extra = finding.allDependencyPaths().size() - 1;
            Log.report("      %s %s", Log.dim("   "),
                    Log.dim("+ " + extra + " other dependency path" + (extra == 1 ? "" : "s")));
            if (Log.isVerbose()) {
                finding.allDependencyPaths().stream().skip(1)
                        .forEach(path -> Log.report("      %s", Log.dim("   " + path)));
            }
        }

        for (String note : finding.notes()) {
            Log.report("      %s %s", Log.dim("note"), note);
        }

        for (String warning : finding.linkageWarnings()) {
            Log.report("      %s %s", Log.yellow("link"), warning);
        }
    }

    private static String severityBadge(int rank) {
        String label = VersionPolicy.severityLabel(rank);
        return switch (rank) {
            case 4 -> Log.red(Log.bold(label));
            case 3 -> Log.red(label);
            case 2 -> Log.yellow(label);
            case 1 -> Log.blue(label);
            default -> Log.dim(label);
        };
    }

    private static String summariseIssues(ScanReport.Finding finding) {
        List<ScanReport.Issue> issues = finding.issues();
        if (issues == null || issues.isEmpty()) {
            return null;
        }
        // A component with 20 CVEs would drown the report; the identifiers are what people
        // paste into a tracker, so show a handful and count the rest.
        List<String> shown = issues.stream()
                .map(ScanReport.Issue::reference)
                .filter(reference -> reference != null && !reference.isBlank())
                .distinct()
                .limit(Log.isVerbose() ? Integer.MAX_VALUE : 4)
                .toList();
        if (shown.isEmpty()) {
            return null;
        }
        String joined = String.join(", ", shown);
        int hidden = (int) issues.stream().map(ScanReport.Issue::reference).distinct().count() - shown.size();
        return hidden > 0 ? joined + Log.dim(" (+" + hidden + " more)") : joined;
    }

    /** Findings that are neither wins nor risks: not in this module, not actually affected. */
    private static void renderInformational(ScanReport report) {
        List<ScanReport.Finding> informational = report.findings().stream()
                .filter(f -> f.outcome() == ScanReport.Outcome.NOT_IN_GRAPH)
                .toList();
        if (informational.isEmpty()) {
            return;
        }
        Log.report("");
        Log.report(Log.dim("NOT REACHABLE FROM THIS POM (" + informational.size() + ")"));
        Log.report(Log.dim("  Reported by the scanner but absent from this module's resolved graph."));
        Log.report(Log.dim("  Common in multi-module builds — run the tool against the owning module."));
        for (ScanReport.Finding finding : informational) {
            Log.report(Log.dim("  · " + finding.gav()));
        }
    }

    private static void renderSummary(ScanReport report) {
        Map<ScanReport.Outcome, Long> counts = report.outcomeCounts();
        Log.report("");
        Log.report(Log.dim("─".repeat(64)));

        long fixed = count(counts, ScanReport.Outcome.FIXED) + count(counts, ScanReport.Outcome.WOULD_FIX);
        long notAffected = count(counts, ScanReport.Outcome.NOT_AFFECTED);
        List<ScanReport.Finding> outstanding = report.outstanding();

        StringBuilder summary = new StringBuilder();
        summary.append(Log.green(fixed + " fixed"));
        if (notAffected > 0) {
            summary.append(" · ").append(notAffected).append(" not affected");
        }
        if (!outstanding.isEmpty()) {
            summary.append(" · ").append(Log.red(outstanding.size() + " outstanding"))
                    .append(" (highest: ")
                    .append(severityBadge(report.highestOutstandingSeverity()))
                    .append(")");
        }
        Log.report(Log.bold("Summary  ") + summary);

        if (report.dryRun() && fixed > 0) {
            Log.report(Log.yellow("Dry run — no POM was modified. Re-run without --dry-run to apply."));
        }
    }

    private static long count(Map<ScanReport.Outcome, Long> counts, ScanReport.Outcome outcome) {
        return counts.getOrDefault(outcome, 0L);
    }

    static String humanDuration(Duration duration) {
        long seconds = duration.toSeconds();
        if (seconds < 60) {
            return seconds + "s";
        }
        return (seconds / 60) + "m " + (seconds % 60) + "s";
    }
}
