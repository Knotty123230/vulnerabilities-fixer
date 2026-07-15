package com.vulncheck;

import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.eclipse.aether.DefaultRepositorySystemSession;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.supplier.RepositorySystemSupplier;

import java.nio.file.Path;

public final class MavenResolverFactory {

    private MavenResolverFactory() {
    }

    public static RepositorySystem createRepositorySystem() {
        return new RepositorySystemSupplier().get();
    }

    public static RepositorySystemSession createSession(
            RepositorySystem repositorySystem,
            Path localRepositoryPath
    ) {
        DefaultRepositorySystemSession session = MavenRepositorySystemUtils.newSession();
        session.setUpdatePolicy(RepositoryPolicy.UPDATE_POLICY_ALWAYS);
        session.setChecksumPolicy(RepositoryPolicy.CHECKSUM_POLICY_IGNORE);

        LocalRepository localRepository =
                new LocalRepository(localRepositoryPath);

        session.setLocalRepositoryManager(
                repositorySystem.newLocalRepositoryManager(
                        session,
                        localRepository
                )
        );
        session.setOffline(false);
        return session;
    }
}
