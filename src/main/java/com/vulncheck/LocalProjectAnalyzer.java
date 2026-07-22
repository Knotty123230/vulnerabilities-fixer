package com.vulncheck;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.apache.maven.model.Model;
import org.apache.maven.model.building.DefaultModelBuilderFactory;
import org.apache.maven.model.building.DefaultModelBuildingRequest;
import org.apache.maven.model.building.ModelBuilder;
import org.apache.maven.model.building.ModelBuildingException;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.collection.CollectResult;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.Dependency; // Aether Dependency
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.DependencyVisitor;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactDescriptorException;
import org.eclipse.aether.resolution.ArtifactDescriptorRequest;
import org.eclipse.aether.resolution.ArtifactDescriptorResult;

public class LocalProjectAnalyzer {

    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession repositorySystemSession;
    private final List<RemoteRepository> repositories;

    public LocalProjectAnalyzer(final RepositorySystem repositorySystem,
            final RepositorySystemSession repositorySystemSession, final List<RemoteRepository> repositories) {
        this.repositorySystem = repositorySystem;
        this.repositorySystemSession = repositorySystemSession;
        this.repositories = repositories;
    }

    public Artifact getParentCandidate(final File pomFile) throws IOException, XmlPullParserException {
        final MavenXpp3Reader reader = new MavenXpp3Reader();
        final Model rawModel = reader.read(new FileReader(pomFile));
        if (rawModel.getParent() != null) {
            return new DefaultArtifact(
                    rawModel.getParent().getGroupId(),
                    rawModel.getParent().getArtifactId(),
                    null,
                    "pom",
                    rawModel.getParent().getVersion());
        }
        return null;
    }

    // ... інші методи класу ...

    /**
     * Шукає BOM у секції dependencyManagement поточного pom.xml,
     * який містить (керує) вказаною цільовою залежністю.
     */
    public org.apache.maven.model.Dependency findBomManagingDependency(final File pomFile,
            final Artifact targetDependency) throws Exception {
        final MavenXpp3Reader reader = new MavenXpp3Reader();
        final Model rawModel = reader.read(new FileReader(pomFile));

        if (rawModel.getDependencyManagement() == null) {
            return null;
        }

        // 1. Знаходимо всі імпортовані BOM у поточному pom.xml
        final List<org.apache.maven.model.Dependency> importedBoms = rawModel.getDependencyManagement()
                .getDependencies().stream()
                .filter(d -> "pom".equals(d.getType()) && "import".equals(d.getScope()))
                .toList();

        // 2. Проходимо по кожному BOM, завантажуємо його і перевіряємо, чи є там наша
        // залежність
        for (final org.apache.maven.model.Dependency bom : importedBoms) {

            // Версія BOM може бути вказана через property (напр. ${quarkus.version})
            final String bomVersion = resolveVersionProperty(bom.getVersion(), rawModel);

            final Artifact bomArtifact = new DefaultArtifact(bom.getGroupId(), bom.getArtifactId(), "pom", bomVersion);

            // Формуємо запит до Aether для читання дескриптора (POM) цього BOM-у
            final ArtifactDescriptorRequest descriptorRequest = new ArtifactDescriptorRequest();

            descriptorRequest.setArtifact(bomArtifact);
            descriptorRequest.setRepositories(repositories);

            try {
                final ArtifactDescriptorResult descriptorResult = repositorySystem
                        .readArtifactDescriptor(repositorySystemSession, descriptorRequest);

                // 3. Перевіряємо, чи є в managedDependencies цього BOM-у наш вразливий артефакт
                final boolean managesTarget = descriptorResult.getManagedDependencies().stream()
                        .anyMatch(managedDep -> managedDep.getArtifact().getGroupId()
                                .equals(targetDependency.getGroupId()) &&
                                managedDep.getArtifact().getArtifactId().equals(targetDependency.getArtifactId()));

                if (managesTarget) {
                    return bom;
                }
            } catch (final ArtifactDescriptorException e) {
                System.err.println("Не вдалося завантажити BOM: " + bomArtifact + ". " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Допоміжний метод: якщо версія записана як ${my.version}, витягує її значення
     * з секції <properties>.
     */
    private String resolveVersionProperty(final String version, final Model rawModel) {
        if (version != null && version.startsWith("${") && version.endsWith("}")) {
            final String propertyName = version.substring(2, version.length() - 1);
            return rawModel.getProperties().getProperty(propertyName, version);
        }
        return version;
    }

    public enum UpdateStrategy {
        EXPLICIT_VERSION,
        MANAGED_BY_PARENT,
        MANAGED_BY_BOM,
        NOT_FOUND
    }

    public UpdateStrategy determineUpdateStrategy(final File pomFile, final String groupId, final String artifactId)
            throws IOException, XmlPullParserException {
        final MavenXpp3Reader reader = new MavenXpp3Reader();
        final Model rawModel = reader.read(new FileReader(pomFile));

        final Optional<org.apache.maven.model.Dependency> rawDependency = rawModel.getDependencies().stream()
                .filter(d -> d.getGroupId().equals(groupId) && d.getArtifactId().equals(artifactId))
                .findFirst();

        if (rawDependency.isEmpty()) {
            return UpdateStrategy.NOT_FOUND;
        }

        final org.apache.maven.model.Dependency dep = rawDependency.get();

        // Якщо версія вказана явно - все просто
        if (dep.getVersion() != null) {
            return UpdateStrategy.EXPLICIT_VERSION;
        }

        // Перевіряємо чи є прямий managed entry для цієї залежності в
        // dependencyManagement
        if (rawModel.getDependencyManagement() != null) {
            final boolean directlyManagedHere = rawModel.getDependencyManagement().getDependencies().stream()
                    .filter(d -> !"pom".equals(d.getType()) || !"import".equals(d.getScope()))
                    .anyMatch(d -> d.getGroupId().equals(groupId) && d.getArtifactId().equals(artifactId));
            if (directlyManagedHere) {
                return UpdateStrategy.EXPLICIT_VERSION; // Версія задана прямо в dependencyManagement
            }

            // Перевіряємо чи є BOM-імпорти що можуть керувати цією залежністю
            final boolean hasImportedBoms = rawModel.getDependencyManagement().getDependencies().stream()
                    .anyMatch(d -> "pom".equals(d.getType()) && "import".equals(d.getScope()));
            if (hasImportedBoms) {
                return UpdateStrategy.MANAGED_BY_BOM;
            }
        }

        // Якщо dependencyManagement порожній або не містить BOM-ів, але є <parent>
        if (rawModel.getParent() != null) {
            return UpdateStrategy.MANAGED_BY_PARENT;
        }

        throw new IllegalStateException(
                "Dependency " + artifactId + " has no version, no parent, and no dependencyManagement.");
    }

    /**
     * Будує граф транзитивних залежностей через Maven Resolver (Aether).
     */
    public DependencyNode buildGraphFromPom(final File pomFile)
            throws ModelBuildingException, DependencyCollectionException {
        final ModelBuilder modelBuilder = new DefaultModelBuilderFactory().newInstance();
        final DefaultModelBuildingRequest defaultModelBuildingRequest = new DefaultModelBuildingRequest()
                .setPomFile(pomFile)
                .setSystemProperties(System.getProperties())
                .setValidationLevel(DefaultModelBuildingRequest.VALIDATION_LEVEL_MINIMAL)
                .setModelResolver(new AetherModelResolver(repositorySystem, repositorySystemSession, repositories));

        final Model effectiveModel = modelBuilder.build(defaultModelBuildingRequest).getEffectiveModel();

        final List<Dependency> aetherDependencies = effectiveModel.getDependencies().stream()
                .map(d -> {
                    final Artifact artifact = new DefaultArtifact(
                            d.getGroupId(), d.getArtifactId(), d.getClassifier(), d.getType(), d.getVersion());
                    return new Dependency(artifact, d.getScope());
                })
                .toList();

        final CollectRequest collectRequest = new CollectRequest();
        collectRequest.setDependencies(aetherDependencies);
        collectRequest.setRepositories(repositories);

        final CollectResult collectResult = repositorySystem.collectDependencies(repositorySystemSession,
                collectRequest);

        return collectResult.getRoot();
    }

    /**
     * Знаходить пряму залежність у проєкті, яка тягне за собою вразливу
     * транзитивну.
     */
    public Artifact findDirectDependencyForVulnerability(final DependencyNode rootNode, final String groupId,
            final String artifactId) {
        final List<DependencyNode> currentPath = new ArrayList<>();
        final Artifact[] directDependencyCandidate = new Artifact[1];

        rootNode.accept(new DependencyVisitor() {
            @Override
            public boolean visitEnter(final DependencyNode node) {
                currentPath.add(node);

                final Artifact artifact = node.getArtifact();
                // Виправлено: правильне порівняння groupId з groupId та artifactId з artifactId
                if (artifact != null &&
                        artifact.getGroupId().equals(groupId) &&
                        artifact.getArtifactId().equals(artifactId)) {

                    // currentPath.get(0) - це root (сам проєкт)
                    // currentPath.get(1) - це пряма залежність з pom.xml
                    if (currentPath.size() > 1) {
                        directDependencyCandidate[0] = currentPath.get(1).getArtifact();
                    }
                }
                // Продовжуємо обхід, бо може бути кілька шляхів до однієї бібліотеки
                return true;
            }

            @Override
            public boolean visitLeave(final DependencyNode node) {
                currentPath.remove(currentPath.size() - 1);
                return true;
            }
        });

        return directDependencyCandidate[0];
    }
}
