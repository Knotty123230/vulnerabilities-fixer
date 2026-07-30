package com.vulncheck;

import org.eclipse.aether.util.version.GenericVersionScheme;
import org.eclipse.aether.version.InvalidVersionSpecificationException;
import org.eclipse.aether.version.Version;

import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Ordering and selection of candidate upgrade versions.
 *
 * <p>Version ordering delegates to Maven's own {@link GenericVersionScheme}, i.e. the exact
 * algorithm the resolver uses for conflict mediation. Hand-rolled string comparison gets this
 * wrong in ways that matter: lexicographically {@code "1.10" < "1.9"}, and a qualifier like
 * {@code 1.0-alpha} must sort <em>below</em> {@code 1.0} while {@code 1.0-sp1} sorts above it.
 */
public final class VersionPolicy {

    /** How far the tool is allowed to move a version to clear a vulnerability. */
    public enum UpgradeScope {
        /** Only {@code x.y.Z} bumps. Safest; often insufficient. */
        PATCH,
        /** {@code x.Y.z} bumps within the same major. The sane CI default. */
        MINOR,
        /** Any newer version, including a new major. Expect source-incompatible changes. */
        MAJOR;

        public String describe() {
            return switch (this) {
                case PATCH -> "same major.minor (patch upgrades only)";
                case MINOR -> "same major (minor and patch upgrades)";
                case MAJOR -> "any newer version, including new majors";
            };
        }
    }

    private static final GenericVersionScheme SCHEME = new GenericVersionScheme();

    /**
     * Qualifiers that mark a build as not generally available. Deliberately a closed list:
     * a blanket "any version with a dash is a pre-release" rule would throw away legitimate
     * releases such as {@code 32.1.3-jre}, {@code 4.1.100.Final} or {@code 1.2.3-sp1}.
     */
    private static final Pattern PRE_RELEASE = Pattern.compile(
            "(?i).*[.\\-_](m\\d+|rc\\d*|cr\\d*|alpha\\d*|beta\\d*|a\\d+|b\\d+|snapshot|ea|preview|pre|dev|incubating)([.\\-_].*)?$");

    /** Parsing the same version string thousands of times across a scan is measurable. */
    private static final Map<String, Version> PARSE_CACHE = new ConcurrentHashMap<>();

    private VersionPolicy() {
    }

    /** Ascending comparator using Maven's version semantics. */
    public static Comparator<String> ascending() {
        return VersionPolicy::compare;
    }

    /** Descending comparator — used when the newest acceptable version should win. */
    public static Comparator<String> descending() {
        return ascending().reversed();
    }

    public static int compare(String left, String right) {
        return parse(left).compareTo(parse(right));
    }

    private static Version parse(String raw) {
        return PARSE_CACHE.computeIfAbsent(raw, v -> {
            try {
                return SCHEME.parseVersion(v);
            } catch (InvalidVersionSpecificationException e) {
                // GenericVersionScheme in practice never rejects input, but the checked
                // exception is part of the contract. Treat unparseable input as lowest.
                throw new IllegalArgumentException("Unparseable version: " + v, e);
            }
        });
    }

    public static boolean isPreRelease(String version) {
        return PRE_RELEASE.matcher(version).matches();
    }

    /** {@code "3.5.14"} → {@code "3.5"}; {@code "4"} → {@code "4"}. */
    public static String majorMinor(String version) {
        String[] parts = numericPrefix(version);
        if (parts.length >= 2) {
            return parts[0] + "." + parts[1];
        }
        return parts.length == 1 ? parts[0] : version;
    }

    /** {@code "3.5.14"} → {@code "3"}. */
    public static String major(String version) {
        String[] parts = numericPrefix(version);
        return parts.length >= 1 ? parts[0] : version;
    }

    /**
     * Splits off the leading numeric components, stopping at the first qualifier.
     * {@code "4.1.100.Final"} → {@code ["4","1","100"]}.
     */
    private static String[] numericPrefix(String version) {
        String[] tokens = version.split("[.\\-_]");
        int count = 0;
        while (count < tokens.length && tokens[count].chars().allMatch(Character::isDigit)
                && !tokens[count].isEmpty()) {
            count++;
        }
        String[] result = new String[count];
        System.arraycopy(tokens, 0, result, 0, count);
        return result;
    }

    /**
     * Builds the ordered list of upgrade candidates for {@code currentVersion}.
     *
     * <p>Candidates are strictly newer, generally available, and within {@code scope}.
     * They are returned <b>ascending</b> so the caller tries the smallest sufficient bump
     * first — the least disruptive fix that actually clears the vulnerability wins.
     */
    public static List<String> candidates(Collection<String> available, String currentVersion, UpgradeScope scope) {
        return available.stream()
                .filter(v -> !isPreRelease(v))
                .filter(v -> compare(v, currentVersion) > 0)
                .filter(v -> withinScope(v, currentVersion, scope))
                .sorted(ascending())
                .distinct()
                .toList();
    }

    private static boolean withinScope(String candidate, String current, UpgradeScope scope) {
        return switch (scope) {
            case PATCH -> majorMinor(candidate).equals(majorMinor(current));
            case MINOR -> major(candidate).equals(major(current));
            case MAJOR -> true;
        };
    }

    /**
     * Decides whether {@code resolvedVersion} of an artifact is still affected, given the set of
     * versions the scanner declared as remediated.
     *
     * <p>A plain {@code resolved >= min(remediation)} test is wrong whenever the vendor backports
     * the fix: with remediations {@code [1.9.5, 2.1.0]}, version {@code 2.0.3} is <em>affected</em>
     * even though it sorts above {@code 1.9.5}. So a version counts as fixed only if it reaches a
     * remediation on its own release line, or exceeds every remediation offered.
     */
    public static boolean isStillAffected(String resolvedVersion, String vulnerableVersion,
                                          Collection<String> remediationVersions) {
        if (resolvedVersion.equals(vulnerableVersion)) {
            return true;
        }
        if (remediationVersions.isEmpty()) {
            // Nothing to compare against: only the exact known-bad version is provably affected.
            return false;
        }

        String resolvedLine = majorMinor(resolvedVersion);
        boolean fixedOnOwnLine = remediationVersions.stream()
                .filter(fix -> majorMinor(fix).equals(resolvedLine))
                .anyMatch(fix -> compare(resolvedVersion, fix) >= 0);
        if (fixedOnOwnLine) {
            return false;
        }

        boolean aboveEverything = remediationVersions.stream()
                .allMatch(fix -> compare(resolvedVersion, fix) > 0);
        return !aboveEverything;
    }

    /** Human-readable label for a version move, e.g. {@code "3.5.14 → 3.5.18 (patch)"}. */
    public static String describeJump(String from, String to) {
        String kind;
        if (!major(from).equals(major(to))) {
            kind = "major";
        } else if (!majorMinor(from).equals(majorMinor(to))) {
            kind = "minor";
        } else {
            kind = "patch";
        }
        return from + " -> " + to + " (" + kind + ")";
    }

    /**
     * Normalises a severity into a comparable ordinal (4 = critical … 1 = low, 0 = unknown).
     *
     * <p>Sonatype Lifecycle reports {@code securityIssues[].severity} as a raw CVSS score,
     * so numeric input is banded per the CVSS v3 qualitative scale; named levels from other
     * scanners are accepted too.
     */
    public static int severityRank(String severity) {
        if (severity == null || severity.isBlank()) {
            return 0;
        }
        try {
            double cvss = Double.parseDouble(severity.trim());
            if (cvss >= 9.0) {
                return 4;
            }
            if (cvss >= 7.0) {
                return 3;
            }
            if (cvss >= 4.0) {
                return 2;
            }
            return cvss > 0 ? 1 : 0;
        } catch (NumberFormatException notAScore) {
            return switch (severity.toLowerCase(Locale.ROOT)) {
                case "critical" -> 4;
                case "severe", "high" -> 3;
                case "moderate", "medium" -> 2;
                case "low", "info", "informational" -> 1;
                default -> 0;
            };
        }
    }

    /** Inverse of {@link #severityRank}, for display and for {@code --fail-on} parsing. */
    public static String severityLabel(int rank) {
        return switch (rank) {
            case 4 -> "CRITICAL";
            case 3 -> "HIGH";
            case 2 -> "MEDIUM";
            case 1 -> "LOW";
            default -> "UNKNOWN";
        };
    }
}
