package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.openrewrite.*;
import org.openrewrite.internal.InMemoryLargeSourceSet;
import org.openrewrite.maven.ChangeProjectVersion;
import org.openrewrite.maven.MavenParser;
import org.openrewrite.maven.UpgradeDependencyVersion;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class MavenPomFixer {


    private void fixPom(Artifact artifact, Path pomFile, String newVersion) throws IOException {
        String fileContent = Files.readString(pomFile);
        ExecutionContext ctx = new InMemoryExecutionContext(Throwable::printStackTrace);

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
            // Беремо першу (і єдину) зміну.
            // getAfter() повертає нове LST дерево, яке ми конвертуємо назад у текст
            SourceFile updatedFile = results.getFirst().getAfter();
            if (updatedFile != null) {
                Files.writeString(pomFile, updatedFile.printAll());
                System.out.println("✅ Версія залежності " + artifact.getArtifactId() + " оновлена до " + newVersion);
            }
        } else {
            System.out.println("ℹ️ Змін не відбулося. Залежність не знайдена або версія вже актуальна.");
        }
    }

    public void updatePomFile(File pomFile, Artifact directDependency, List<String> newerVersions) {
        for (String newVersion : newerVersions) {
            try {
                fixPom(directDependency, pomFile.toPath(), newVersion);
                break;
            } catch (IOException e) {
                System.err.println("❌ Помилка при оновленні версії залежності: " + e.getMessage());
            }
        }
        System.out.println();
    }
}
