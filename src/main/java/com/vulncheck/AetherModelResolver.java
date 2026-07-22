package com.vulncheck;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.Parent;
import org.apache.maven.model.Repository;
import org.apache.maven.model.building.FileModelSource;
import org.apache.maven.model.building.ModelSource;
import org.apache.maven.model.resolution.InvalidRepositoryException;
import org.apache.maven.model.resolution.ModelResolver;
import org.apache.maven.model.resolution.UnresolvableModelException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.VersionRangeRequest;
import org.eclipse.aether.resolution.VersionRangeResolutionException;
import org.eclipse.aether.resolution.VersionRangeResult;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * A minimal {@link ModelResolver} backed by Maven Resolver (Aether) so that
 * {@code ModelBuilder} can fetch parent/imported POMs (e.g. spring-boot-starter-parent)
 * from the configured remote repositories, not just the local pom file being analyzed.
 *
 * Maven's own {@code org.apache.maven.repository.internal.DefaultModelResolver} does the
 * same job but is package-private, so it cannot be reused directly outside Maven core.
 */
public class AetherModelResolver implements ModelResolver {

    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession session;
    private List<RemoteRepository> repositories;

    public AetherModelResolver(RepositorySystem repositorySystem,
                                RepositorySystemSession session,
                                List<RemoteRepository> repositories) {
        this.repositorySystem = repositorySystem;
        this.session = session;
        this.repositories = new ArrayList<>(repositories);
    }

    @Override
    public ModelSource resolveModel(String groupId, String artifactId, String version)
            throws UnresolvableModelException {
        Artifact pomArtifact = new DefaultArtifact(groupId, artifactId, "pom", version);
        try {
            ArtifactRequest request = new ArtifactRequest(pomArtifact, repositories, null);
            pomArtifact = repositorySystem.resolveArtifact(session, request).getArtifact();
        } catch (ArtifactResolutionException e) {
            throw new UnresolvableModelException(e.getMessage(), groupId, artifactId, version, e);
        }

        File pomFile = pomArtifact.getFile();
        return new FileModelSource(pomFile);
    }

    @Override
    public ModelSource resolveModel(Parent parent) throws UnresolvableModelException {
        try {
            resolveHighestVersion(parent.getGroupId(), parent.getArtifactId(), parent.getVersion(),
                    parent::setVersion);
            return resolveModel(parent.getGroupId(), parent.getArtifactId(), parent.getVersion());
        } catch (VersionRangeResolutionException e) {
            throw new UnresolvableModelException(
                    e.getMessage(), parent.getGroupId(), parent.getArtifactId(), parent.getVersion(), e);
        }
    }

    @Override
    public ModelSource resolveModel(Dependency dependency) throws UnresolvableModelException {
        try {
            resolveHighestVersion(dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion(),
                    dependency::setVersion);
            return resolveModel(dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion());
        } catch (VersionRangeResolutionException e) {
            throw new UnresolvableModelException(
                    e.getMessage(), dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion(), e);
        }
    }

    private void resolveHighestVersion(String groupId, String artifactId, String version,
                                        java.util.function.Consumer<String> versionSetter)
            throws VersionRangeResolutionException, UnresolvableModelException {
        Artifact artifact = new DefaultArtifact(groupId, artifactId, "pom", version);
        VersionRangeRequest rangeRequest = new VersionRangeRequest(artifact, repositories, null);
        VersionRangeResult rangeResult = repositorySystem.resolveVersionRange(session, rangeRequest);


        if (rangeResult.getHighestVersion() == null) {
            throw new UnresolvableModelException(
                    "No versions matched the requested range '" + version + "'",
                    groupId, artifactId, version);
        }

        versionSetter.accept(rangeResult.getHighestVersion().toString());
    }

    @Override
    public void addRepository(Repository repository) throws InvalidRepositoryException {
        addRepository(repository, false);
    }

    @Override
    public void addRepository(Repository repository, boolean replace) throws InvalidRepositoryException {
        // Repositories declared inside dependency POMs are ignored; we only use the
        // repositories explicitly configured for this tool (e.g. the project's Nexus).
    }

    @Override
    public ModelResolver newCopy() {
        return new AetherModelResolver(repositorySystem, session, repositories);
    }
}
