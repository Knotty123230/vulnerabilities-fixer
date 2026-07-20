package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.openrewrite.*;
import org.openrewrite.internal.InMemoryLargeSourceSet;
import org.openrewrite.maven.AddManagedDependency;
import org.openrewrite.maven.ChangeDependencyGroupIdAndArtifactId;
import org.openrewrite.maven.ChangeParentPom;
import org.openrewrite.maven.MavenExecutionContextView;
import org.openrewrite.maven.MavenParser;
import org.openrewrite.maven.UpgradeDependencyVersion;
import org.openrewrite.maven.tree.MavenRepository;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class MavenPomFixer {

    private final NexusCredentials credentials;

    public MavenPomFixer(NexusCredentials credentials) {
        this.credentials = credentials;
    }

    private ExecutionContext createContext() {
        ExecutionContext ctx = new InMemoryExecutionContext(Throwable::printStackTrace);
        MavenExecutionContextView mavenCtx = MavenExecutionContextView.view(ctx);
        MavenRepository nexusRepo = new MavenRepository(
                "nexus",
                credentials.url(),
                "true",
                "true",
                credentials.username(),
                credentials.password(),
                null
        );
        mavenCtx.setRepositories(List.of(nexusRepo));
        mavenCtx.setAddCentralRepository(false);
        return ctx;
    }

    private List<SourceFile> parsePomFromFile(ExecutionContext ctx, Path pomFile) {
        MavenParser parser = MavenParser.builder().build();
        var input = new Parser.Input(pomFile, () -> {
            try {
                return Files.newInputStream(pomFile);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        return parser.parseInputs(List.of(input), pomFile.getParent(), ctx)
                .filter(sf -> !(sf instanceof org.openrewrite.tree.ParseError))
                .toList();
    }

    /**
     * Runs a recipe and returns the modified content, or null if no changes.
     */
    private String runRecipe(Recipe recipe, List<SourceFile> docs, ExecutionContext ctx) {
        RecipeRun run = recipe.run(new InMemoryLargeSourceSet(docs), ctx);
        List<Result> results = run.getChangeset().getAllResults();
        if (!results.isEmpty()) {
            SourceFile updated = results.getFirst().getAfter();
            if (updated != null) {
                return updated.printAll();
            }
        }
        return null;
    }

    /**
     * Creates the appropriate recipe based on the artifact type:
     * - For "pom" extension (BOM/parent artifacts): uses ChangeDependencyGroupIdAndArtifactId
     *   which works on dependencyManagement entries directly
     * - For regular dependencies: uses UpgradeDependencyVersion with overrideManagedVersion
     */
    private List<Recipe> createRecipes(Artifact artifact, String newVersion) {
        String ext = artifact.getExtension();
        // For BOM artifacts (type=pom), use ChangeDependencyGroupIdAndArtifactId
        // which can modify dependencyManagement entries directly
        if ("pom".equals(ext)) {
            return List.of(
                    // Try ChangeParentPom first (handles <parent> section)
                    // retainVersions=["*"] keeps all existing explicit version overrides intact
                    new ChangeParentPom(
                            artifact.getGroupId(),
                            artifact.getGroupId(),
                            artifact.getArtifactId(),
                            artifact.getArtifactId(),
                            newVersion,
                            null,
                            null,
                            null,
                            true,
                            List.of("*:*")
                    ),
                    // Then try ChangeDependencyGroupIdAndArtifactId with same group/artifact
                    // (handles BOM imports in dependencyManagement)
                    new ChangeDependencyGroupIdAndArtifactId(
                            artifact.getGroupId(),
                            artifact.getArtifactId(),
                            artifact.getGroupId(),
                            artifact.getArtifactId(),
                            newVersion,
                            null,
                            true,
                            true
                    )
            );
        }
        // For regular dependencies
        return List.of(
                new UpgradeDependencyVersion(
                        artifact.getGroupId(),
                        artifact.getArtifactId(),
                        newVersion,
                        null,
                        true,
                        null
                )
        );
    }

    public void updatePomFile(File pomFile, Artifact directDependency, String newerVersion) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePomFromFile(ctx, pomFile.toPath());

            for (Recipe recipe : createRecipes(directDependency, newerVersion)) {
                String result = runRecipe(recipe, docs, ctx);
                if (result != null) {
                    Files.writeString(pomFile.toPath(), result);
                    System.out.println("✅ Версія залежності " + directDependency.getArtifactId() + " оновлена до " + newerVersion);
                    return;
                }
            }
            System.out.println("ℹ️ Не вдалося оновити " + directDependency.getArtifactId() + " до " + newerVersion);
        } catch (Exception e) {
            System.err.println("❌ Помилка при оновленні версії залежності: " + e.getMessage());
        }
    }

    public String updatePomDryRun(File pomFile, Artifact directDependency, String newerVersion) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePomFromFile(ctx, pomFile.toPath());

            for (Recipe recipe : createRecipes(directDependency, newerVersion)) {
                String result = runRecipe(recipe, docs, ctx);
                if (result != null) {
                    System.out.println("DRY RUN ℹ️: Знайдено працюючий рецепт для версії " + newerVersion);
                    return result;
                }
            }
        } catch (Exception e) {
            System.err.println("❌ Помилка при симуляції оновлення (Dry Run): " + e.getMessage());
        }
        return null;
    }

    /**
     * Adds or updates an explicit version override in dependencyManagement for the
     * vulnerable transitive artifact. First tries UpgradeDependencyVersion (updates
     * existing entry), then falls back to AddManagedDependency (creates new entry).
     */
    public void addManagedDependencyOverride(File pomFile, String groupId, String artifactId, String version) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePomFromFile(ctx, pomFile.toPath());

            // First try: upgrade existing managed dependency entry
            var upgradeRecipe = new UpgradeDependencyVersion(groupId, artifactId, version, null, true, null);
            String result = runRecipe(upgradeRecipe, docs, ctx);
            if (result != null) {
                Files.writeString(pomFile.toPath(), result);
                System.out.println("✅ Оновлено managed dependency: " + groupId + ":" + artifactId + ":" + version);
                return;
            }

            // Second try: add new managed dependency entry
            var addRecipe = new AddManagedDependency(groupId, artifactId, version,
                    null, null, null, null, null, groupId + ":" + artifactId, null, null);
            result = runRecipe(addRecipe, docs, ctx);
            if (result != null) {
                Files.writeString(pomFile.toPath(), result);
                System.out.println("✅ Додано managed dependency override: " + groupId + ":" + artifactId + ":" + version);
            } else {
                System.out.println("ℹ️ Не вдалося додати/оновити managed dependency для " + groupId + ":" + artifactId);
            }
        } catch (Exception e) {
            System.err.println("❌ Помилка при додаванні managed dependency: " + e.getMessage());
        }
    }

    /**
     * Dry-run version: tries upgrade first, then add.
     */
    public String addManagedDependencyOverrideDryRun(File pomFile, String groupId, String artifactId, String version) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePomFromFile(ctx, pomFile.toPath());

            // First try upgrade existing
            var upgradeRecipe = new UpgradeDependencyVersion(groupId, artifactId, version, null, true, null);
            String result = runRecipe(upgradeRecipe, docs, ctx);
            if (result != null) {
                System.out.println("DRY RUN ℹ️: Оновлено managed dependency " + artifactId + ":" + version);
                return result;
            }

            // Then try add new
            var addRecipe = new AddManagedDependency(groupId, artifactId, version,
                    null, null, null, null, null, groupId + ":" + artifactId, null, null);
            result = runRecipe(addRecipe, docs, ctx);
            if (result != null) {
                System.out.println("DRY RUN ℹ️: Додано managed dependency override для " + artifactId + ":" + version);
                return result;
            }
        } catch (Exception e) {
            System.err.println("❌ Помилка при симуляції AddManagedDependency: " + e.getMessage());
        }
        return null;
    }
}
