package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts quarantined artifacts from Maven build output.
 *
 * <p>Static analysis of a POM can only probe what it can enumerate, and a build resolves more than
 * any enumeration covers: Maven plugins, annotation processors, framework augmentation classpaths,
 * and — for Quarkus — a bootstrap resolver that performs its own version mediation and can settle
 * on a different version than the project's dependency graph does. Reading the failure removes the
 * guesswork: whatever the build could not fetch, it names.
 *
 * <p>Maven stops at the first refusal, so one log usually reveals one artifact. Clearing a whole
 * project therefore means fixing and re-running until the build gets past resolution.
 */
public final class BuildLogQuarantineScanner {

    /**
     * Artifact coordinates as Aether prints them: {@code group:artifact:extension[:classifier]:version}.
     */
    private static final Pattern COORDINATE = Pattern.compile(
            "artifact\\s+([A-Za-z0-9_.\\-]+):([A-Za-z0-9_.\\-]+):([A-Za-z0-9_.\\-]+)"
                    + "(?::([A-Za-z0-9_.\\-]+))?:([A-Za-z0-9_.\\-]+)");

    /** One artifact the firewall refused, as reported by the build. */
    public record Hit(Artifact artifact, String quarantineUrl) {

        public String gav() {
            return artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion();
        }
    }

    private BuildLogQuarantineScanner() {
    }

    /**
     * Finds every quarantined coordinate mentioned in {@code buildOutput}, de-duplicated.
     *
     * <p>Scans line by line and only accepts a coordinate from a line that also names the
     * quarantine. Aether repeats the same failure through several nested exceptions, and the
     * surrounding stack frames mention plenty of unrelated coordinates.
     */
    public static List<Hit> scan(String buildOutput) {
        if (buildOutput == null || buildOutput.isBlank()) {
            return List.of();
        }

        Map<String, Hit> hits = new LinkedHashMap<>();
        for (String line : buildOutput.split("\\R")) {
            if (!line.toLowerCase(Locale.ROOT).contains("quarantine")) {
                continue;
            }
            QuarantineDetector.Verdict verdict =
                    QuarantineDetector.inspect(new IllegalStateException(line));
            if (!verdict.quarantined()) {
                continue;
            }
            for (Artifact artifact : coordinatesIn(line)) {
                hits.putIfAbsent(key(artifact), new Hit(artifact, verdict.quarantineUrl()));
            }
        }

        List<Hit> found = List.copyOf(hits.values());
        if (!found.isEmpty()) {
            Log.debug("Build output names %d quarantined artifact(s)", found.size());
        }
        return found;
    }

    private static List<Artifact> coordinatesIn(String line) {
        List<Artifact> artifacts = new ArrayList<>();
        Matcher matcher = COORDINATE.matcher(line);
        while (matcher.find()) {
            String extension = matcher.group(3);
            String classifier = matcher.group(4);
            String version = matcher.group(5);
            artifacts.add(new DefaultArtifact(
                    matcher.group(1), matcher.group(2),
                    classifier == null ? "" : classifier,
                    extension, version));
        }
        return artifacts;
    }

    private static String key(Artifact artifact) {
        return artifact.getGroupId() + ":" + artifact.getArtifactId()
                + ":" + artifact.getExtension() + ":" + artifact.getVersion();
    }
}
