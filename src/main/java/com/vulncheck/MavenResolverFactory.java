package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.MirrorSelector;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.supplier.RepositorySystemSupplier;
import org.eclipse.aether.supplier.SessionBuilderSupplier;

import java.nio.file.Path;
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

    /**
     * The repositories artifacts are looked up in: the configured Nexus, or Maven Central when
     * there is none.
     */
    public static List<RemoteRepository> createRepositories(NexusCredentials credentials) {
        if (credentials == null) {
            return List.of(new RemoteRepository.Builder("central", "default", CENTRAL_URL).build());
        }
        return List.of(new RemoteRepository.Builder("nexus", "default", credentials.url())
                .setAuthentication(credentials.toAuthentication())
                .build());
    }

    public static RepositorySystemSession createSession(RepositorySystem repositorySystem, Path localRepositoryPath) {
        return createSession(repositorySystem, localRepositoryPath, null);
    }

    /**
     * Builds the resolution session.
     *
     * <p>When a Nexus is configured, every other repository is mirrored through it. Transitive
     * POMs frequently declare their own {@code <repositories>}, and Aether's descriptor reader
     * would otherwise reach straight out to them — which fails on a corporate network that only
     * allows the internal mirror, and quietly bypasses that mirror on one that does not.
     */
    public static RepositorySystemSession createSession(RepositorySystem repositorySystem,
                                                        Path localRepositoryPath,
                                                        NexusCredentials nexusCredentials) {
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
        builder.setOffline(false);
        builder.setSystemProperties(System.getProperties());
        builder.withLocalRepositoryBaseDirectories(localRepositoryPath);

        if (nexusCredentials != null) {
            builder.setMirrorSelector(mirrorEverythingThrough(nexusCredentials));
        }

        return builder.build();
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
