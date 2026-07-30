package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import org.junit.jupiter.api.Assumptions;

import java.util.List;

/**
 * Shared resolver wiring for the network-backed tests.
 *
 * <p>These tests resolve real artifacts, so they honour the machine's {@code settings.xml} exactly
 * as the tool does. Hard-coding Maven Central here would make the suite fail on any developer
 * behind a corporate mirror — reported as a broken test rather than as the unreachable network it
 * actually is. When the repository genuinely cannot be reached the tests are
 * <em>skipped</em>, because an offline machine is not a regression.
 */
final class TestRepositories {

    private static final String PROBE_GROUP = "org.apache.commons";
    private static final String PROBE_ARTIFACT = "commons-text";

    private TestRepositories() {
    }

    record Wiring(RepositorySystem system, RepositorySystemSession session,
                  List<RemoteRepository> repositories) {

        LocalProjectAnalyzer analyzer() {
            return new LocalProjectAnalyzer(system, session, repositories);
        }
    }

    static Wiring create() {
        MavenUserSettings settings = MavenUserSettings.load();
        RepositorySystem system = MavenResolverFactory.createRepositorySystem();
        RepositorySystemSession session =
                MavenResolverFactory.createSession(system, settings.localRepository(), null, settings);
        List<RemoteRepository> repositories =
                MavenResolverFactory.createRepositories(system, session, null, settings);
        return new Wiring(system, session, repositories);
    }

    /**
     * Skips the calling test unless artifact metadata can actually be fetched. Uses the resolver
     * itself rather than a raw socket check, so a mirror that is reachable but does not proxy
     * Central is caught too.
     */
    static Wiring requireReachableRepository() {
        Wiring wiring = create();
        try {
            List<String> versions = new VersionCatalog(wiring.system(), wiring.session(), wiring.repositories())
                    .availableVersions(PROBE_GROUP, PROBE_ARTIFACT, "jar");
            Assumptions.assumeTrue(versions.contains("1.10.0"),
                    () -> "Skipping: " + wiring.repositories().getFirst().getUrl()
                            + " does not serve " + PROBE_GROUP + ":" + PROBE_ARTIFACT
                            + " (resolved " + versions.size() + " version(s)). "
                            + "Configure ~/.m2/settings.xml or run with -Dtest.excludedGroups=network.");
        } catch (RuntimeException e) {
            Assumptions.abort("Skipping: artifact repository is unreachable — " + Log.describe(e));
        }
        return wiring;
    }
}
