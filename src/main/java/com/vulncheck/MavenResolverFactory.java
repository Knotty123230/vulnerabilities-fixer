package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.LocalRepository;
import org.eclipse.aether.supplier.RepositorySystemSupplier;
import org.eclipse.aether.supplier.SessionBuilderSupplier;

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
        var sessionBuilder =
                new SessionBuilderSupplier(repositorySystem).get();

        var temporarySession = sessionBuilder.build();

        LocalRepository localRepository =
                new LocalRepository(localRepositoryPath);

        sessionBuilder.setLocalRepositoryManager(
                repositorySystem.newLocalRepositoryManager(
                        temporarySession,
                        localRepository
                )
        );

        sessionBuilder.setOffline(false);

        return sessionBuilder.build();
    }
}
