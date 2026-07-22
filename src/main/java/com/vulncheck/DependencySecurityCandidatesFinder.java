package com.vulncheck;

import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.repository.RemoteRepository;
import org.jspecify.annotations.NonNull;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class DependencySecurityCandidatesFinder {

    private final SonatypeScanReport report;
    private final NexusVersionResolver nexusVersionResolver;
    private final LocalProjectAnalyzer localProjectAnalyzer;
    private final MavenPomFixer mavenPomFixer;
    private final LinkageMavenChecker linkageMavenChecker;
    private static final List<String> LOCKSTEP_GROUPS = List.of(
            "ch.qos.logback",
            "org.slf4j",
            "com.fasterxml.jackson.core",
            "com.fasterxml.jackson.datatype",
            "org.springframework",
            "io.netty");

    public DependencySecurityCandidatesFinder(SonatypeScanReport report, RepositorySystem repositorySystem,
                                              RepositorySystemSession repository, NexusCredentials credentials) {
        this.report = report;
        this.nexusVersionResolver = new NexusVersionResolver(repositorySystem, repository, credentials);
        mavenPomFixer = new MavenPomFixer(credentials);
        localProjectAnalyzer = new LocalProjectAnalyzer(repositorySystem, repository,
                List.of(new RemoteRepository.Builder(
                        "nexus",
                        "default",
                        credentials.url())
                        .setAuthentication(credentials.toAuthentication())
                        .build()));
        linkageMavenChecker = new LinkageMavenChecker();
    }

    public void findDependencySecurityCandidates(File pomFile) throws Exception {
        // Build the dependency graph ONCE — it's expensive (network I/O to resolve
        // parent/transitive POMs)
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

            Artifact directDependency = localProjectAnalyzer.findDirectDependencyForVulnerability(dependencyNode,
                    vulnerabilityDetails.groupId(), vulnerabilityDetails.artifactId());
            if (directDependency == null) {
                System.out.println("Вразливість не знайдена у графі залежностей.");
                return;
            }
            var updateStrategy = localProjectAnalyzer.determineUpdateStrategy(pomFile, directDependency.getGroupId(),
                    directDependency.getArtifactId());

            switch (updateStrategy) {
                case EXPLICIT_VERSION -> {
                    List<String> newerVersions = fixNewVersionAndFix(directDependency);
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
                    System.out.println("Потрібно оновити версію Parent POM або відповідну property.");
                    Artifact parent = localProjectAnalyzer.getParentCandidate(pomFile);
                    boolean fixed = findAndFix(pomFile, parent, vulnerabilityDetails);
                    // Fallback: if no same-minor parent update fixes the vuln,
                    // add explicit dependencyManagement override for the vulnerable artifact
                    if (!fixed) {
                        System.out.println("Parent update в рамках " + (parent != null
                                ? parent.getVersion().substring(0, parent.getVersion().lastIndexOf(".")) + ".x"
                                : "?") + " не допоміг.");
                        System.out.println("Додаємо explicit managed dependency override для вразливого артефакту...");
                        overrideDependency(pomFile, vulnerabilityDetails);
                    }
                }

                case MANAGED_BY_BOM -> {
                    // Версією керує BOM у <dependencyManagement>.
                    // Спочатку шукаємо BOM що керує прямою залежністю
                    org.apache.maven.model.Dependency bomDep = localProjectAnalyzer.findBomManagingDependency(pomFile,
                            directDependency);
                    // Якщо не знайшли BOM для прямої, пробуємо шукати для вразливого артефакту
                    if (bomDep == null) {
                        DefaultArtifact vulnArtifact = new DefaultArtifact(
                                vulnerabilityDetails.groupId(),
                                vulnerabilityDetails.artifactId(),
                                "jar",
                                vulnerabilityDetails.version());
                        bomDep = localProjectAnalyzer.findBomManagingDependency(pomFile, vulnArtifact);
                    }

                    if (bomDep != null) {
                        System.out.println("Знайдено BOM: " + bomDep.getGroupId() + ":" + bomDep.getArtifactId() + ":"
                                + bomDep.getVersion());
                        List<String> newerBomVersions = fixNewVersionAndFix(new DefaultArtifact(
                                bomDep.getGroupId(),
                                bomDep.getArtifactId(),
                                "pom",
                                bomDep.getVersion()));
                        for (String newerVersion : newerBomVersions) {
                            DefaultArtifact art = new DefaultArtifact(bomDep.getGroupId(), bomDep.getArtifactId(),
                                    "pom", bomDep.getVersion());
                            String pomContent = mavenPomFixer.updatePomDryRun(pomFile, art, newerVersion);
                            if (verifyDryRunFix(pomContent, vulnerabilityDetails)) {
                                mavenPomFixer.updatePomFile(pomFile, art, newerVersion);
                                break;
                            }
                        }
                    } else {
                        // Fallback: якщо BOM не знайдено, спробуємо оновити parent
                        System.out.println("BOM не знайдено, пробуємо оновити Parent POM...");
                        var parent = localProjectAnalyzer.getParentCandidate(pomFile);

                        boolean fixed = findAndFix(pomFile, parent, vulnerabilityDetails);

                        // Last resort: add explicit managed dependency override
                        if (!fixed) {
                            System.out.println("Додаємо explicit managed dependency override...");
                            overrideDependency(pomFile, vulnerabilityDetails);
                        }
                    }
                }

                case NOT_FOUND -> System.out.println(
                        "Пряма залежність не знайдена в поточному файлі (можливо вона в іншому модулі багатомодульного проєкту).");
            }
            if (linkageMavenChecker.hasLinkageErrors(pomFile.toPath())) {
                System.out.println("⚠️ Попередження: після оновлення версії залежності виявлено помилки зв'язування (linkage errors). для компонента " + String.format("%s:%s:%s", vulnerabilityDetails.groupId(), vulnerabilityDetails.artifactId(), vulnerabilityDetails.version()));
            }
        }


    }

    private void overrideDependency(File pomFile, Vulnerability vulnerabilityDetails) {
        List<String> remediationVersions = vulnerabilityDetails.versionToFix();
        for (String fixVersion : remediationVersions) {
            if (fixVersion.equals(vulnerabilityDetails.version()))
                continue; // skip current version
            String dryResult = mavenPomFixer.addManagedDependencyOverrideDryRun(pomFile,
                    vulnerabilityDetails.groupId(), vulnerabilityDetails.artifactId(), fixVersion);
            if (verifyDryRunFix(dryResult, vulnerabilityDetails)) {
                mavenPomFixer.addManagedDependencyOverride(pomFile,
                        vulnerabilityDetails.groupId(), vulnerabilityDetails.artifactId(), fixVersion);
                break;
            }
        }
    }

    private List<String> fixNewVersionAndFix(Artifact directDependency) {
        List<String> newerVersions = new ArrayList<>(nexusVersionResolver.getNewerVersions(
                directDependency.getGroupId(),
                directDependency.getArtifactId(),
                directDependency.getVersion()));
        newerVersions = new ArrayList<>(
                filterSameMajorVersion(newerVersions, directDependency.getVersion()));
        newerVersions.sort(Comparator.comparing(i -> i.substring(i.lastIndexOf("."))));
        return newerVersions;
    }

    private boolean findAndFix(File pomFile, Artifact parent, Vulnerability vulnerabilityDetails) {
        if (parent != null) {
            List<String> newerParentVersions = fixNewVersionAndFix(parent);

            for (String newerVersion : newerParentVersions) {
                String pomContent = mavenPomFixer.updatePomDryRun(pomFile, parent, newerVersion);
                if (verifyDryRunFix(pomContent, vulnerabilityDetails)) {
                    mavenPomFixer.updatePomFile(pomFile, parent, newerVersion);
                    return true;
                }
            }

        }
        return false;
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
                directDependency.getVersion());
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
        if (updatedPomXml == null) {
            System.out.println(
                    "DRY RUN ❌: Рецепт не згенерував змін (версія можливо задана через property або BOM parent).");
            return false;
        }

        File tempPom = null;
        try {
            // 1. Створюємо тимчасовий файл, бо Aether потребує фізичного файлу для
            // розв'язання шляхів
            tempPom = File.createTempFile("pom-dry-run-", ".xml");
            Files.writeString(tempPom.toPath(), updatedPomXml);

            System.out.println("DRY RUN ℹ️: Будуємо новий граф залежностей для перевірки...");

            // 2. Будуємо граф з тимчасового файлу
            DependencyNode newRootNode = localProjectAnalyzer.buildGraphFromPom(tempPom);

            // 3. Перевіряємо, чи залишилась вразлива версія у новому графі
            boolean isStillVulnerable = isVulnerabilityPresentInGraph(newRootNode, vuln);

            if (isStillVulnerable) {
                System.out.println("DRY RUN ❌: Оновлення застосовано, але вразлива версія " + vuln.version()
                        + " ВСЕ ЩЕ присутня у графі (можливо притягується транзитивно іншим шляхом).");
                return false;
            } else {
                System.out.println(
                        "DRY RUN ✅: Успіх! Новий граф зібрався, вразлива версія " + vuln.version() + " видалена.");
                var hasErrors = linkageMavenChecker.hasLinkageErrors(tempPom.toPath());
                return !hasErrors;
            }

        } catch (Exception e) {
            System.err.println("DRY RUN ❌: Оновлений POM-файл зламав збірку графа: " + e.getMessage());
        } finally {
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

    /**
     * Filters version list to only include versions with the same major.minor
     * version as currentVersion.
     * Excludes milestones, RCs, alphas, betas.
     * E.g. currentVersion="3.5.14" → keeps "3.5.15", "3.5.16" but removes "3.6.0",
     * "4.0.0", "4.0.0-M1"
     * E.g. currentVersion="4.0.7" → keeps "4.0.8", "4.0.9" but removes "4.1.0"
     */
    private List<String> filterSameMajorVersion(List<String> versions, String currentVersion) {
        String[] currentParts = currentVersion.split("\\.");
        String currentMajorMinor = currentParts.length >= 2
                ? currentParts[0] + "." + currentParts[1]
                : currentParts[0];
        return versions.stream()
                .filter(v -> {
                    String[] parts = v.split("\\.");
                    String majorMinor = parts.length >= 2 ? parts[0] + "." + parts[1] : parts[0];
                    return majorMinor.equals(currentMajorMinor);
                })
                .filter(v -> !v.matches(".*-(M\\d+|RC\\d+|alpha\\d*|beta\\d*|SNAPSHOT).*"))
                .toList();
    }
}
