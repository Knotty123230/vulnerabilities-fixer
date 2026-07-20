package com.vulncheck;

import org.apache.maven.artifact.handler.ArtifactHandler;
import org.apache.maven.model.Model;
import org.apache.maven.model.building.DefaultModelBuilderFactory;
import org.apache.maven.model.building.DefaultModelBuildingRequest;
import org.apache.maven.model.building.ModelBuilder;
import org.apache.maven.model.building.ModelBuildingException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.collection.CollectResult;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.DependencyVisitor;
import org.eclipse.aether.repository.RemoteRepository;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class LocalProjectAnalyzer {

    private  final RepositorySystem repositorySystem;
    private final RepositorySystemSession repositorySystemSession;
    private final List<RemoteRepository> repositories;


    public LocalProjectAnalyzer(RepositorySystem repositorySystem, RepositorySystemSession repositorySystemSession, List<RemoteRepository> repositories) {
        this.repositorySystem = repositorySystem;
        this.repositorySystemSession = repositorySystemSession;
        this.repositories = repositories;
    }


    public DependencyNode buildGraphFromPom(File pomFile) throws ModelBuildingException, DependencyCollectionException {
        ModelBuilder modelBuilder = new DefaultModelBuilderFactory().newInstance();
        DefaultModelBuildingRequest defaultModelBuildingRequest = new DefaultModelBuildingRequest()
                .setPomFile(pomFile)
                .setSystemProperties(System.getProperties())
                .setValidationLevel(DefaultModelBuildingRequest.VALIDATION_LEVEL_MINIMAL);

        Model effectiveModel = modelBuilder.build(defaultModelBuildingRequest).getEffectiveModel();
        List<Dependency> aetherDependencies = effectiveModel.getDependencies().stream()
                .map(d -> {
                    Artifact artifact = new DefaultArtifact(
                            d.getGroupId(), d.getArtifactId(), d.getClassifier(), d.getType(), d.getVersion()
                    );
                    return new Dependency(artifact, d.getScope());
                })
                .toList();


        CollectRequest collectRequest = new CollectRequest();
        collectRequest.setDependencies(aetherDependencies);
        collectRequest.setRepositories(repositories); // Твій Nexus

        // 4. Просимо Aether побудувати дерево
        CollectResult collectResult = repositorySystem.collectDependencies(repositorySystemSession, collectRequest);

        return collectResult.getRoot();
    }


    public Artifact findDirectDependencyForVulnerability(DependencyNode rootNode, String artifactId, String groupId) {
        List<DependencyNode> currentPath = new ArrayList<>();
        Artifact[] directDependecyCandidate = new Artifact[1];
        rootNode.accept(new DependencyVisitor() {
            @Override
            public boolean visitEnter(DependencyNode node) {
                currentPath.add(node);

                Artifact artifact = node.getArtifact();
                if (artifact != null &&
                        artifact.getGroupId().equals(artifactId) &&
                        artifact.getArtifactId().equals(groupId)) {

                    // currentPath.get(0) - це root (сам проект)
                    // currentPath.get(1) - це пряма залежність з pom.xml
                    if (currentPath.size() > 1) {
                        directDependecyCandidate[0] = currentPath.get(1).getArtifact();
                    }
                }
                // Продовжуємо обхід, навіть якщо знайшли (бо може бути кілька шляхів)
                return true;
            }

            @Override
            public boolean visitLeave(DependencyNode node) {
                currentPath.removeLast();
                return true;
            }
        });

        return directDependecyCandidate[0];
    }
}
