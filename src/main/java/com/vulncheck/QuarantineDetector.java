package com.vulncheck;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Recognises a Sonatype Repository Firewall quarantine among resolution failures.
 *
 * <p>A quarantined component is refused by the proxy with HTTP 403 and a body naming the
 * quarantine, e.g.
 * <pre>
 * status code: 403, reason phrase: ---->>> REQUESTED ITEM IS QUARANTINED ---->>> FOR DETAILS
 * SEE ---->>> https://iq.example.com/ui/links/firewall/repositories/quarantinedComponent/MzdhOD... &lt;&lt;&lt;----
 * </pre>
 *
 * <p>This is worth telling apart from an ordinary 403. A plain authorization failure means the
 * credentials are wrong and no version will work; a quarantine means <em>this specific version</em>
 * violates a policy while other versions of the same artifact are very likely fine. The two call
 * for opposite responses, so the message body — not just the status code — decides.
 *
 * <p>Aether wraps transport failures several layers deep, so the whole cause chain is inspected.
 */
public final class QuarantineDetector {

    private static final String QUARANTINE_MARKER = "quarantine";
    /** Any URL in the message; the firewall link is then picked out by path. */
    private static final Pattern URL = Pattern.compile("https?://[^\\s<>\"]+");
    private static final String FIREWALL_PATH = "/ui/links/firewall/";
    /**
     * Every phrasing of a 403 seen across resolver transports. Maven 3.9's HTTP transport reports
     * {@code status code: 403, reason phrase: ...} and carries the response body with it; the
     * resolver 2.x Apache transport reports only {@code HTTP Status: 403} and discards the body,
     * which is why a 403 alone is never enough to conclude "quarantine".
     */
    private static final Pattern STATUS_403 = Pattern.compile(
            "status code:\\s*403|http status:\\s*403|\\(403\\)|\\b403\\b\\s*forbidden");
    /** The message decorates the link with arrows and dashes, e.g. {@code ...MzdhOD<<<------}. */
    private static final Pattern TRAILING_NOISE = Pattern.compile("[<>.,;:)\\]}\\-]+$");

    /** What a failed download turned out to be. */
    public record Verdict(boolean quarantined, boolean forbidden, String quarantineUrl, String detail) {

        static final Verdict NOT_QUARANTINE = new Verdict(false, false, null, null);
    }

    private QuarantineDetector() {
    }

    /**
     * Inspects several related failures as one.
     *
     * <p>Needed because {@link org.eclipse.aether.resolution.ArtifactResolutionException} keeps the
     * transport failure in its {@code getResult().getExceptions()} list rather than in its cause
     * chain. Its own message degrades to a bare "could not be resolved ... (absent)", so looking
     * only at the cause chain reports a quarantined artifact as merely missing — and the tool would
     * then discard the version for the wrong reason and never surface the firewall link.
     */
    public static Verdict inspect(Iterable<? extends Throwable> failures) {
        StringBuilder combined = new StringBuilder();
        for (Throwable failure : failures) {
            if (failure != null) {
                combined.append(flatten(failure));
            }
        }
        return inspectText(combined.toString());
    }

    /** Inspects a failure and reports whether the firewall quarantined the artifact. */
    public static Verdict inspect(Throwable failure) {
        return inspectText(flatten(failure));
    }

    private static Verdict inspectText(String combined) {
        if (combined.isEmpty()) {
            return Verdict.NOT_QUARANTINE;
        }

        String lower = combined.toLowerCase(Locale.ROOT);
        boolean forbidden = STATUS_403.matcher(lower).find();
        if (!lower.contains(QUARANTINE_MARKER)) {
            return new Verdict(false, forbidden, null, forbidden ? "HTTP 403 from the repository" : null);
        }

        return new Verdict(true, forbidden, extractFirewallLink(combined),
                "component is quarantined by Sonatype Repository Firewall");
    }

    /**
     * Pulls the quarantined-component link out of the message.
     *
     * <p>The link is worth surfacing: it opens the violation detail without authentication, and is
     * the fastest route to deciding whether to bump the version or ask for a policy waiver. It
     * expires 12 hours after the component is first quarantined.
     */
    private static String extractFirewallLink(String message) {
        Matcher matcher = URL.matcher(message);
        while (matcher.find()) {
            String candidate = TRAILING_NOISE.matcher(matcher.group()).replaceAll("");
            if (candidate.contains(FIREWALL_PATH)) {
                return candidate;
            }
        }
        return null;
    }

    public static boolean isQuarantined(Throwable failure) {
        return inspect(failure).quarantined();
    }

    public static Optional<String> quarantineUrl(Throwable failure) {
        return Optional.ofNullable(inspect(failure).quarantineUrl());
    }

    /** Concatenates every message in the cause chain, guarding against cyclic causes. */
    private static String flatten(Throwable failure) {
        StringBuilder sb = new StringBuilder();
        Throwable current = failure;
        int depth = 0;
        while (current != null && depth < 20) {
            if (current.getMessage() != null) {
                sb.append(current.getMessage()).append('\n');
            }
            Throwable next = current.getCause();
            if (next == current) {
                break;
            }
            current = next;
            depth++;
        }
        return sb.toString();
    }
}
