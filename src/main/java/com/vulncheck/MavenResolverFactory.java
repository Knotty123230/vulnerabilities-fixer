package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.MirrorSelector;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.supplier.RepositorySystemSupplier;
import org.eclipse.aether.supplier.SessionBuilderSupplier;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Wiring for Maven Resolver: one repository system, one session, one repository list. */
public final class MavenResolverFactory {

    public static final String CENTRAL_URL = "https://repo.maven.apache.org/maven2/";

    private MavenResolverFactory() {
    }

    public static RepositorySystem createRepositorySystem() {
        return new RepositorySystemSupplier().get();
    }

    public static Path defaultLocalRepository() {
        return Path.of(System.getProperty("user.home"), ".m2", "repository");
    }

    public static RepositorySystemSession createSession(RepositorySystem repositorySystem, Path localRepositoryPath) {
        return createSession(repositorySystem, localRepositoryPath, null, null);
    }

    public static RepositorySystemSession createSession(RepositorySystem repositorySystem,
                                                        Path localRepositoryPath,
                                                        NexusCredentials nexusCredentials) {
        return createSession(repositorySystem, localRepositoryPath, nexusCredentials, null);
    }

    /**
     * Builds the resolution session.
     *
     * <p>Configuration precedence is: an explicit {@code --nexus-url} wins, otherwise the user's
     * {@code settings.xml} applies, otherwise plain Central. An explicit Nexus mirrors <em>every</em>
     * repository, including those declared inside transitive POMs — Aether's descriptor reader
     * would otherwise reach straight out to them, which fails on a network that only allows the
     * internal mirror and quietly bypasses that mirror on one that does not.
     *
     * @param settings the user's Maven settings, or {@code null} to ignore them
     */
    public static RepositorySystemSession createSession(RepositorySystem repositorySystem,
                                                        Path localRepositoryPath,
                                                        NexusCredentials nexusCredentials,
                                                        MavenUserSettings settings) {
        // Must come from SessionBuilderSupplier, which ships with the same resolver version as
        // the RepositorySystem above. The older MavenRepositorySystemUtils.newSession() from
        // maven-resolver-provider is built against the resolver 1.9 API: it produces a session
        // that resolver 2.x accepts but collects only direct dependencies from — every transitive
        // dependency silently disappears, and with it every verdict this tool makes.
        RepositorySystemSession.SessionBuilder builder = new SessionBuilderSupplier(repositorySystem).get();

        // Released artifacts are immutable, so a daily metadata refresh is plenty. UPDATE_POLICY_ALWAYS
        // re-fetched maven-metadata.xml on every single version lookup and dominated scan time.
        builder.setUpdatePolicy(RepositoryPolicy.UPDATE_POLICY_DAILY);
        // A security tool must not silently accept a corrupted artifact; warn rather than ignore.
        builder.setChecksumPolicy(RepositoryPolicy.CHECKSUM_POLICY_WARN);
        builder.setSystemProperties(System.getProperties());
        builder.setOffline(settings != null && settings.isOffline());
        builder.withLocalRepositoryBaseDirectories(localRepositoryPath);

        if (nexusCredentials != null) {
            builder.setMirrorSelector(mirrorEverythingThrough(nexusCredentials));
        } else if (settings != null) {
            builder.setMirrorSelector(settings.mirrorSelector());
            builder.setProxySelector(settings.proxySelector());
            builder.setAuthenticationSelector(settings.authenticationSelector());
        }

        return builder.build();
    }

    public static List<RemoteRepository> createRepositories(NexusCredentials credentials) {
        return createRepositories(null, null, credentials, null);
    }

    /**
     * The repositories artifacts are looked up in.
     *
     * <p>The result is passed through {@link RepositorySystem#newResolutionRepositories} whenever a
     * session is available. That call is what actually applies the session's mirror, proxy and
     * authentication selectors to each repository — build the list by hand and skip it, and a
     * perfectly configured {@code settings.xml} has no effect whatsoever.
     */
    public static List<RemoteRepository> createRepositories(RepositorySystem repositorySystem,
                                                            RepositorySystemSession session,
                                                            NexusCredentials credentials,
                                                            MavenUserSettings settings) {
        List<RemoteRepository> repositories = new ArrayList<>();

        if (credentials != null) {
            repositories.add(new RemoteRepository.Builder("nexus", "default", credentials.url())
                    .setAuthentication(credentials.toAuthentication())
                    .build());
        } else {
            repositories.add(new RemoteRepository.Builder("central", "default", CENTRAL_URL).build());
            if (settings != null) {
                repositories.addAll(settings.activeProfileRepositories());
            }
        }

        if (repositorySystem == null || session == null) {
            return List.copyOf(repositories);
        }
        return List.copyOf(repositorySystem.newResolutionRepositories(session, repositories));
    }

    private static MirrorSelector mirrorEverythingThrough(NexusCredentials credentials) {
        return repository -> {
            // Mirroring the Nexus with itself would recurse.
            if ("nexus".equals(repository.getId())) {
                return null;
            }
            return new RemoteRepository.Builder(
                    "nexus-mirror-" + repository.getId(), repository.getContentType(), credentials.url())
                    .setAuthentication(credentials.toAuthentication())
                    .build();
        };
    }
}
