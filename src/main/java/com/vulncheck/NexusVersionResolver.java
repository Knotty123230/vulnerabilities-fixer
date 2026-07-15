package com.vulncheck;

import org.apache.maven.model.building.ModelProblem;
import org.apache.maven.repository.internal.MavenRepositorySystemUtils;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.ArtifactType;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.VersionRangeRequest;
import org.eclipse.aether.resolution.VersionRangeResolutionException;
import org.eclipse.aether.resolution.VersionRangeResult;
import org.eclipse.aether.util.repository.AuthenticationBuilder;
import org.eclipse.aether.version.Version;

import java.util.List;
import java.util.Map;
import java.util.Objects;

public class NexusVersionResolver {
    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession session;
    private final String nexusUrl;
    private  String nexusUsername;
    private  String nexusPassword;

    public NexusVersionResolver(
            RepositorySystem repositorySystem,
            RepositorySystemSession session,
            String nexusUrl,
            String nexusUsername,
            String nexusPassword
    ) {
        this.repositorySystem = Objects.requireNonNull(
                repositorySystem,
                "repositorySystem"
        );
        this.session = Objects.requireNonNull(session, "session");
        this.nexusUrl = normalizeUrl(nexusUrl);
        this.nexusUsername = Objects.requireNonNull(nexusUsername, "nexusUsername");
        this.nexusPassword = Objects.requireNonNull(nexusPassword, "nexusPassword");
    }

    public List<String> getAvailableVersions(
            String groupId,
            String artifactId
    ) {
        requireNonBlank(groupId, "groupId");
        requireNonBlank(artifactId, "artifactId");
        Authentication authentication = new AuthenticationBuilder()
                .addUsername(nexusUsername)
                .addPassword(nexusPassword)
                .build();

        RemoteRepository repository = new RemoteRepository.Builder(
                "nexus",
                "default",
                nexusUrl
        )
                .setAuthentication(authentication)
                .build();

        Artifact artifact = new DefaultArtifact(
                groupId,
                artifactId,
                "jar",
                "[0,)"
        );

        VersionRangeRequest request = new VersionRangeRequest(
                artifact,
                List.of(repository),
                null
        );

        try {
            VersionRangeResult result =
                    repositorySystem.resolveVersionRange(session, request);

            return result.getVersions()
                    .stream()
                    .map(Version::toString)
                    .toList();

        } catch (VersionRangeResolutionException exception) {
            throw new IllegalStateException(
                    "Cannot retrieve versions for "
                            + groupId
                            + ":"
                            + artifactId
                            + " from "
                            + nexusUrl,
                    exception
            );
        }
    }

    public String getLatestVersion(
            String groupId,
            String artifactId
    ) {
        List<String> versions = getAvailableVersions(groupId, artifactId);

        if (versions.isEmpty()) {
            throw new IllegalStateException(
                    "No versions found for "
                            + groupId
                            + ":"
                            + artifactId
            );
        }

        return versions.getLast();
    }

    private static String normalizeUrl(String url) {
        String value = requireNonBlank(url, "nexusUrl");

        return value.endsWith("/")
                ? value
                : value + "/";
    }

    private static String requireNonBlank(
            String value,
            String fieldName
    ) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    fieldName + " must not be blank"
            );
        }

        return value;
    }


    public List<String> getNewerVersions(
            String groupId,
            String artifactId,
            String currentVersion
    ) {
        Artifact artifact = new DefaultArtifact(
                groupId,
                artifactId,
                "jar",
                "(" + currentVersion + ",)"
        );

        RemoteRepository repository = new RemoteRepository.Builder(
                "nexus",
                "default",
                nexusUrl
        ).build();

        VersionRangeRequest request = new VersionRangeRequest(
                artifact,
                List.of(repository),
                null
        );

        try {
            return repositorySystem
                    .resolveVersionRange(session, request)
                    .getVersions()
                    .stream()
                    .map(Version::toString)
                    .toList();
        } catch (VersionRangeResolutionException exception) {
            throw new IllegalStateException(
                    "Cannot retrieve versions newer than "
                            + currentVersion
                            + " for "
                            + groupId
                            + ":"
                            + artifactId,
                    exception
            );
        }
    }
}
