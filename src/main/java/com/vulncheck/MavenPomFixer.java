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

    private void fixPom(Artifact artifact, Path pomFile, String newVersion) throws IOException {
        String fileContent = Files.readString(pomFile);
        ExecutionContext ctx = new InMemoryExecutionContext(Throwable::printStackTrace);

        // Configure OpenRewrite to use corporate Nexus instead of Maven Central
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
