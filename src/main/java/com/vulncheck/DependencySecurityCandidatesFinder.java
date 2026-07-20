package com.vulncheck;

import org.apache.maven.model.building.ModelBuildingException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.repository.RemoteRepository;

import java.io.File;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class DependencySecurityCandidatesFinder {

    private final SonatypeScanReport report;
    private final NexusVersionResolver nexusVersionResolver;
    private final LocalProjectAnalyzer localProjectAnalyzer;
    private final MavenPomFixer mavenPomFixer;



    public DependencySecurityCandidatesFinder(SonatypeScanReport report, RepositorySystem repositorySystem, RepositorySystemSession repository, NexusCredentials credentials) {
        this.report = report;
        this.nexusVersionResolver = new NexusVersionResolver(repositorySystem, repository, credentials);
        mavenPomFixer = new MavenPomFixer();
        localProjectAnalyzer = new LocalProjectAnalyzer(repositorySystem, repository, List.of(new RemoteRepository.Builder(
                "nexus",
                "default",
                credentials.url()
        )
                .setAuthentication(credentials.toAuthentication())
                .build()));
    }

    public void findDependencySecurityCandidates(File pomFile) throws DependencyCollectionException, ModelBuildingException {
        // Build the dependency graph ONCE — it's expensive (network I/O to resolve parent/transitive POMs)
        DependencyNode dependencyNode = localProjectAnalyzer.buildGraphFromPom(pomFile);

        for (SonatypeScanReport.VulnerabilityDetails vulnerability : report.vulnerabilities()) {
            String packageUrl = vulnerability.packageUrl();
            List<String> versionsToFix = vulnerability.remediationVersions().stream()
                    .map(SonatypeScanReport.RemediationVersion::version)
                    .sorted(Comparator.comparing(i -> i.substring(i.lastIndexOf("."))))
                    .toList();

            Vulnerability vulnerabilityDetails = extractFromPackageUrl(packageUrl, versionsToFix);
            System.out.printf("Вразливий артефакт: %s:%s:%s (рекомендовані виправлення: %s)%n",
                    vulnerabilityDetails.groupId(),
                    vulnerabilityDetails.artifactId(),
                    vulnerabilityDetails.version(),
                    versionsToFix);

            Artifact directDependency = localProjectAnalyzer.findDirectDependencyForVulnerability(dependencyNode, vulnerabilityDetails.groupId(), vulnerabilityDetails.artifactId());
            if (directDependency == null) {
                System.out.println("Вразливість не знайдена у графі залежностей.");
                return;
            }

            System.out.printf("Вразливість притягнута через пряму залежність: %s:%s:%s%n",
                    directDependency.getGroupId(),
                    directDependency.getArtifactId(),
                    directDependency.getVersion());

            // 2. Використовуємо Твій існуючий код для пошуку нових версій
            List<String> newerVersions = nexusVersionResolver.getNewerVersions(
                    directDependency.getGroupId(),
                    directDependency.getArtifactId(),
                    directDependency.getVersion()
            );
            newerVersions.sort(Comparator.comparing(i -> i.substring(i.lastIndexOf("."))));

            mavenPomFixer.updatePomFile(pomFile, directDependency, newerVersions);
        }

    }


    public Vulnerability extractFromPackageUrl(String packageUrl, List<String> versionToFix) {
        packageUrl = packageUrl.replace("pkg:maven/", "");
        String[] parts = packageUrl.split("@");
        String groupIdAndArtifactId = parts[0];
        String version = parts[1];
        String[] groupIdAndArtifactIdParts = groupIdAndArtifactId.split("/");
        String groupId = groupIdAndArtifactIdParts[0];
        String artifactId = groupIdAndArtifactIdParts[1];
        return new Vulnerability(groupId, artifactId, version, versionToFix);

    }
}
