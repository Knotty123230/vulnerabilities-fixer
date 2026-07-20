package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.openrewrite.*;
import org.openrewrite.internal.InMemoryLargeSourceSet;
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

    /**
     * Спільний метод для застосування рецепта.
     * Повертає true, якщо зміни були успішно згенеровані (або застосовані).
     */
    private boolean applyRecipe(Artifact artifact, Path pomFile, String newVersion, boolean isDryRun) throws IOException {
        String fileContent = Files.readString(pomFile);
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

        MavenParser parser = MavenParser.builder().build();
        List<SourceFile> mavenDocuments = parser.parse(ctx, fileContent).toList();

        var changeVersionRequest = new UpgradeDependencyVersion(
                artifact.getGroupId(),
                artifact.getArtifactId(),
                newVersion,
                null,
                null,
                null
        );

        RecipeRun recipeRun = changeVersionRequest.run(new InMemoryLargeSourceSet(mavenDocuments), ctx);
        List<Result> results = recipeRun.getChangeset().getAllResults();

        if (!results.isEmpty()) {
            SourceFile updatedFile = results.getFirst().getAfter();
            if (updatedFile != null) {
                if (isDryRun) {
                    System.out.println("DRY RUN ℹ️: Версія залежності " + artifact.getArtifactId() + " БУЛА Б оновлена до " + newVersion);
                } else {
                    Files.writeString(pomFile, updatedFile.printAll());
                    System.out.println("✅ Версія залежності " + artifact.getArtifactId() + " оновлена до " + newVersion);
                }
                return true; // Рецепт успішно спрацював
            }
        }

        return false; // Рецепт не згенерував змін
    }

    public void updatePomFile(File pomFile, Artifact directDependency, String newerVersion) {
        try {
            applyRecipe(directDependency, pomFile.toPath(), newerVersion, false);
        } catch (IOException e) {
            System.err.println("❌ Помилка при оновленні версії залежності: " + e.getMessage());
        }
    }

    public String updatePomDryRun(File pomFile, Artifact directDependency, String newerVersion) {
        try {
            // 1. Читаємо файл лише один раз
            String fileContent = Files.readString(pomFile.toPath());

            ExecutionContext ctx = new InMemoryExecutionContext(Throwable::printStackTrace);

            // 2. Налаштовуємо доступ до корпоративного Nexus
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

            // 3. Парсимо pom.xml в AST (теж один раз для оптимізації)
            MavenParser parser = MavenParser.builder().build();
            List<SourceFile> mavenDocuments = parser.parse(ctx, fileContent).toList();

            // 4. Перебираємо нові версії
            var changeVersionRequest = new UpgradeDependencyVersion(
                    directDependency.getGroupId(),
                    directDependency.getArtifactId(),
                    newerVersion,
                    null,
                    null,
                    null
            );

            // Виконуємо рецепт
            RecipeRun recipeRun = changeVersionRequest.run(new InMemoryLargeSourceSet(mavenDocuments), ctx);
            List<Result> results = recipeRun.getChangeset().getAllResults();

            if (!results.isEmpty()) {
                SourceFile updatedFile = results.getFirst().getAfter();
                if (updatedFile != null) {
                    System.out.println("DRY RUN ℹ️: Знайдено працюючий рецепт для версії " + newerVersion);
                    return updatedFile.printAll(); // Повертаємо новий XML як строку
                }
            }
        } catch (Exception e) {
            System.err.println("❌ Помилка при симуляції оновлення (Dry Run): " + e.getMessage());
            e.printStackTrace();
        }

        return null; // Жодна версія не підійшла або сталася помилка
    }
}
