package com.vulncheck;

import java.util.List;
import java.util.Map;

/**
 * Renders a {@link ScanReport} as Markdown, sized for a merge-request comment or a
 * GitHub Actions job summary ({@code $GITHUB_STEP_SUMMARY}).
 */
public final class MarkdownReportRenderer {

    private MarkdownReportRenderer() {
    }

    public static String render(ScanReport report) {
        StringBuilder md = new StringBuilder();

        md.append("# Dependency vulnerability report\n\n");
        appendVerdictBadge(md, report);

        md.append("| | |\n|---|---|\n");
        row(md, "Project", code(report.projectPath()));
        if (report.applicationId() != null) {
            row(md, "Application", code(report.applicationId()));
        }
        if (report.sonatypeReportUrl() != null) {
            row(md, "Scan report", "[open](" + report.sonatypeReportUrl() + ")");
        }
        row(md, "Components", report.componentsScanned() + " scanned, " + report.findings().size() + " vulnerable");
        row(md, "Upgrade policy", report.upgradeScope());
        row(md, "Mode", report.dryRun() ? "dry run (no files written)" : "apply");
        row(md, "Duration", ConsoleReportRenderer.humanDuration(report.duration()));
        md.append('\n');

        appendFixedSection(md, report);
        appendOutstandingSection(md, report);
        appendNotReachableSection(md, report);

        md.append("\n---\n");
        md.append(summaryLine(report)).append('\n');
        return md.toString();
    }

    private static void appendVerdictBadge(StringBuilder md, ScanReport report) {
        List<ScanReport.Finding> outstanding = report.outstanding();
        if (outstanding.isEmpty()) {
            md.append("> **No outstanding vulnerabilities.**\n\n");
        } else {
            md.append("> **")
                    .append(outstanding.size())
                    .append(" outstanding vulnerabilit")
                    .append(outstanding.size() == 1 ? "y" : "ies")
                    .append("** — highest severity ")
                    .append(VersionPolicy.severityLabel(report.highestOutstandingSeverity()))
                    .append(".\n\n");
        }
    }

    private static void appendFixedSection(StringBuilder md, ScanReport report) {
        List<ScanReport.Finding> fixed = report.fixed();
        if (fixed.isEmpty()) {
            return;
        }
        md.append("## ").append(report.dryRun() ? "Proposed fixes" : "Applied fixes")
                .append(" (").append(fixed.size()).append(")\n\n");
        md.append("| Component | Severity | Change | Control point |\n");
        md.append("|---|---|---|---|\n");
        for (ScanReport.Finding finding : fixed) {
            md.append("| ").append(code(finding.coordinate()))
                    .append(" | ").append(VersionPolicy.severityLabel(finding.severityRank()))
                    .append(" | ").append(nullSafe(finding.appliedChange()))
                    .append(" | ").append(nullSafe(finding.controlPoint()))
                    .append(" |\n");
        }
        md.append('\n');
    }

    private static void appendOutstandingSection(StringBuilder md, ScanReport report) {
        List<ScanReport.Finding> outstanding = report.outstanding();
        if (outstanding.isEmpty()) {
            return;
        }
        md.append("## Outstanding (").append(outstanding.size()).append(")\n\n");
        for (ScanReport.Finding finding : outstanding) {
            md.append("### ").append(finding.gav())
                    .append(" — ").append(VersionPolicy.severityLabel(finding.severityRank()))
                    .append("\n\n");
            md.append("- **Why unresolved:** ").append(describeOutcome(finding)).append('\n');
            if (finding.dependencyPath() != null) {
                md.append("- **Dependency path:** ").append(code(finding.dependencyPath())).append('\n');
            }
            if (finding.candidateVersions() != null && !finding.candidateVersions().isEmpty()) {
                md.append("- **Versions tried:** ")
                        .append(code(String.join(", ", finding.candidateVersions())))
                        .append('\n');
            }
            appendIssueList(md, finding);
            for (String note : finding.notes()) {
                md.append("- ").append(note).append('\n');
            }
            for (String warning : finding.linkageWarnings()) {
                md.append("- :warning: ").append(warning).append('\n');
            }
            md.append('\n');
        }
    }

    private static void appendIssueList(StringBuilder md, ScanReport.Finding finding) {
        if (finding.issues() == null || finding.issues().isEmpty()) {
            return;
        }
        md.append("- **Advisories:** ");
        md.append(finding.issues().stream()
                .map(issue -> issue.url() != null && !issue.url().isBlank()
                        ? "[" + issue.reference() + "](" + issue.url() + ")"
                        : issue.reference())
                .distinct()
                .limit(10)
                .reduce((a, b) -> a + ", " + b)
                .orElse("—"));
        md.append('\n');
    }

    private static void appendNotReachableSection(StringBuilder md, ScanReport report) {
        List<ScanReport.Finding> notReachable = report.findings().stream()
                .filter(f -> f.outcome() == ScanReport.Outcome.NOT_IN_GRAPH)
                .toList();
        if (notReachable.isEmpty()) {
            return;
        }
        md.append("<details><summary>Not reachable from this POM (")
                .append(notReachable.size()).append(")</summary>\n\n");
        md.append("Reported by the scanner but absent from this module's resolved graph — ")
                .append("usually another module of a multi-module build.\n\n");
        notReachable.forEach(f -> md.append("- ").append(code(f.gav())).append('\n'));
        md.append("\n</details>\n");
    }

    private static String describeOutcome(ScanReport.Finding finding) {
        return switch (finding.outcome()) {
            case NO_REMEDIATION_AVAILABLE -> "the scanner offers no fixed version yet";
            case NO_WORKING_FIX -> "no candidate version within the upgrade policy removed the "
                    + "vulnerable version from the resolved graph";
            case REJECTED_BREAKS_COMPATIBILITY -> "a working version exists but it breaks binary "
                    + "compatibility with code in this build";
            case ERROR -> "the attempt failed for a technical reason (see notes)";
            default -> finding.outcome().name();
        };
    }

    private static String summaryLine(ScanReport report) {
        Map<ScanReport.Outcome, Long> counts = report.outcomeCounts();
        long fixed = counts.getOrDefault(ScanReport.Outcome.FIXED, 0L)
                + counts.getOrDefault(ScanReport.Outcome.WOULD_FIX, 0L);
        return "**Summary:** " + fixed + " fixed · "
                + counts.getOrDefault(ScanReport.Outcome.NOT_AFFECTED, 0L) + " not affected · "
                + report.outstanding().size() + " outstanding";
    }

    private static void row(StringBuilder md, String key, String value) {
        md.append("| **").append(key).append("** | ").append(value).append(" |\n");
    }

    private static String code(String value) {
        return value == null ? "—" : "`" + value + "`";
    }

    private static String nullSafe(String value) {
        return value == null ? "—" : value;
    }
}
