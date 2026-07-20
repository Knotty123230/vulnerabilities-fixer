package com.vulncheck;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.building.ModelBuildingException;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.repository.RemoteRepository;
import org.jspecify.annotations.NonNull;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

public class DependencySecurityCandidatesFinder {

    private final SonatypeScanReport report;
    private final NexusVersionResolver nexusVersionResolver;
    private final LocalProjectAnalyzer localProjectAnalyzer;
    private final MavenPomFixer mavenPomFixer;
    private static final List<String> LOCKSTEP_GROUPS = List.of(
            "ch.qos.logback",
            "org.slf4j",
            "com.fasterxml.jackson.core",
            "com.fasterxml.jackson.datatype",
            "org.springframework",
            "io.netty"
    );



    public DependencySecurityCandidatesFinder(SonatypeScanReport report, RepositorySystem repositorySystem, RepositorySystemSession repository, NexusCredentials credentials) {
        this.report = report;
        this.nexusVersionResolver = new NexusVersionResolver(repositorySystem, repository, credentials);
        mavenPomFixer = new MavenPomFixer(credentials);
        localProjectAnalyzer = new LocalProjectAnalyzer(repositorySystem, repository, List.of(new RemoteRepository.Builder(
                "nexus",
                "default",
                credentials.url()
        )
                .setAuthentication(credentials.toAuthentication())
                .build()));
    }

    public void findDependencySecurityCandidates(File pomFile) throws Exception {
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
            var updateStrategy = localProjectAnalyzer.determineUpdateStrategy(pomFile, directDependency.getGroupId(), directDependency.getArtifactId());

            switch (updateStrategy) {
                case EXPLICIT_VERSION -> {
                    List<String> newerVersions = new ArrayList<>(nexusVersionResolver.getNewerVersions(
                            directDependency.getGroupId(),
                            directDependency.getArtifactId(),
                            directDependency.getVersion()
                    ));
                    newerVersions.sort(Comparator.comparing(i -> i.substring(i.lastIndexOf("."))));

                    // Перевіряємо, чи належить залежність до локстеп-групи
                    Artifact artifactToUpdate = getArtifact(directDependency);
                    for (String newerVersion : newerVersions) {

                        String pomContent = mavenPomFixer.updatePomDryRun(pomFile, artifactToUpdate, newerVersion);
                        if (verifyDryRunFix(pomContent, vulnerabilityDetails)) {
                            mavenPomFixer.updatePomFile(pomFile, artifactToUpdate, newerVersion);
                            break;
                        }
                    }

                }

                case MANAGED_BY_PARENT -> {
                    // Версією керує <parent>.
                    // Тобі треба дістати координати Parent-а (наприклад, org.springframework.boot:spring-boot-starter-parent)
                    // і шукати нові версії ДЛЯ PARENT-а через NexusVersionResolver.

                    System.out.println("Потрібно оновити версію Parent POM або відповідну property.");

                    var parent = localProjectAnalyzer.getParentCandidate(pomFile);
                    if (parent != null) {
                        List<String> newerParentVersions = new ArrayList<>(nexusVersionResolver.getNewerVersions(
                                parent.getGroupId(),
                                parent.getArtifactId(),
                                parent.getVersion()
                        ));
                        newerParentVersions.sort(Comparator.comparing(i -> i.substring(i.lastIndexOf("."))));

                        for (String newerVersion : newerParentVersions) {

                            String pomContent = mavenPomFixer.updatePomDryRun(pomFile, parent, newerVersion);
                            if (verifyDryRunFix(pomContent, vulnerabilityDetails)) {
                                mavenPomFixer.updatePomFile(pomFile, parent, newerVersion);
                                break;
                            }
                        }
                    } else {
                        System.out.println("Parent POM не знайдено.");
                    }
                }

                case MANAGED_BY_BOM -> {
                    // Версією керує BOM у <dependencyManagement>.
                    // Тобі треба знайти, який саме BOM (наприклад, quarkus-bom) притягує цю залежність.
                    System.out.println("Потрібно оновити версію імпортованого BOM-а.");
                    Dependency artifact = localProjectAnalyzer.findBomManagingDependency(pomFile, directDependency);
                    if (artifact != null) {
                        List<String> newerBomVersions = new ArrayList<>(nexusVersionResolver.getNewerVersions(
                                artifact.getGroupId(),
                                artifact.getArtifactId(),
                                artifact.getVersion()
                        ));
                        newerBomVersions.sort(Comparator.comparing(i -> i.substring(i.lastIndexOf("."))));
                        for (String newerVersion : newerBomVersions) {
                            DefaultArtifact art = new DefaultArtifact(artifact.getGroupId(), artifact.getArtifactId(), "pom", artifact.getVersion());
                            String pomContent = mavenPomFixer.updatePomDryRun(pomFile, art, newerVersion);
                            if (verifyDryRunFix(pomContent, vulnerabilityDetails)) {
                                mavenPomFixer.updatePomFile(pomFile, art, newerVersion);
                                break;
                            }
                        }
                    }
                }

                case NOT_FOUND -> {
                    System.out.println("Пряма залежність не знайдена в поточному файлі (можливо вона в іншому модулі багатомодульного проєкту).");
                }
            }
        }

    }

    private static @NonNull Artifact getArtifact(Artifact directDependency) {
        String targetArtifactId = LOCKSTEP_GROUPS.contains(directDependency.getGroupId())
                ? "*"
                : directDependency.getArtifactId();

        // Створюємо "фейковий" артефакт для передачі у MavenPomFixer.
        // Якщо це локстеп, передаємо зірочку замість конкретного імені,
        // щоб оновити всі модулі цієї групи одним махом.
        return new org.eclipse.aether.artifact.DefaultArtifact(
                directDependency.getGroupId(),
                targetArtifactId,
                directDependency.getExtension(),
                directDependency.getVersion()
        );
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


    private boolean verifyDryRunFix(String updatedPomXml, Vulnerability vuln) {
        File tempPom = null;
        try {
            // 1. Створюємо тимчасовий файл, бо Aether потребує фізичного файлу для розв'язання шляхів
            tempPom = File.createTempFile("pom-dry-run-", ".xml");
            Files.writeString(tempPom.toPath(), updatedPomXml);

            System.out.println("DRY RUN ℹ️: Будуємо новий граф залежностей для перевірки...");

            // 2. Будуємо граф з тимчасового файлу
            DependencyNode newRootNode = localProjectAnalyzer.buildGraphFromPom(tempPom);

            // 3. Перевіряємо, чи залишилась вразлива версія у новому графі
            boolean isStillVulnerable = isVulnerabilityPresentInGraph(newRootNode, vuln);
            

            if (isStillVulnerable) {
                System.out.println("DRY RUN ❌: Оновлення застосовано, але вразлива версія " + vuln.version() + " ВСЕ ЩЕ присутня у графі (можливо притягується транзитивно іншим шляхом).");
                return false;
            } else {
                System.out.println("DRY RUN ✅: Успіх! Новий граф зібрався, вразлива версія " + vuln.version() + " видалена.");
                return true;
            }

        } catch (Exception e) {
            System.err.println("DRY RUN ❌: Оновлений POM-файл зламав збірку графа: " + e.getMessage());
        } finally {
            // 4. Обов'язково прибираємо за собою
            if (tempPom != null && tempPom.exists()) {
                tempPom.delete();
            }
        }
        return false;
    }

    private boolean isVulnerabilityPresentInGraph(DependencyNode node, Vulnerability vuln) {
        if (node.getDependency() != null) {
            Artifact artifact = node.getDependency().getArtifact();
            // Якщо координати збігаються І версія досі вразлива
            if (artifact.getGroupId().equals(vuln.groupId()) &&
                    artifact.getArtifactId().equals(vuln.artifactId()) &&
                    artifact.getVersion().equals(vuln.version())) {
                return true;
            }
        }

        // Перевіряємо дочірні вузли
        for (DependencyNode child : node.getChildren()) {
            if (isVulnerabilityPresentInGraph(child, vuln)) {
                return true;
            }
        }

        return false;
    }
}
