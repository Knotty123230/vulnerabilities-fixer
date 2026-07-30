package com.vulncheck;

import org.eclipse.aether.artifact.Artifact;
import org.openrewrite.ExecutionContext;
import org.openrewrite.InMemoryExecutionContext;
import org.openrewrite.Parser;
import org.openrewrite.Recipe;
import org.openrewrite.RecipeRun;
import org.openrewrite.Result;
import org.openrewrite.SourceFile;
import org.openrewrite.internal.InMemoryLargeSourceSet;
import org.openrewrite.maven.AddManagedDependency;
import org.openrewrite.maven.ChangeDependencyGroupIdAndArtifactId;
import org.openrewrite.maven.ChangeParentPom;
import org.openrewrite.maven.MavenExecutionContextView;
import org.openrewrite.maven.MavenParser;
import org.openrewrite.maven.UpgradeDependencyVersion;
import org.openrewrite.maven.tree.MavenRepository;
import org.openrewrite.tree.ParseError;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Produces edited POM content via OpenRewrite recipes.
 *
 * <p>Every operation is expressed as "give me the new XML" — writing to disk is a separate,
 * explicit step. That split is what lets the engine verify a change by resolving it before
 * anything is committed to the working tree, and is what makes {@code --dry-run} exact rather
 * than an approximation.
 */
public class MavenPomFixer {

    private final NexusCredentials credentials;

    public MavenPomFixer(NexusCredentials credentials) {
        this.credentials = credentials;
    }

    /**
     * OpenRewrite resolves POMs through its own Maven client, so it needs the same repository
     * configuration as the resolver. Without a Nexus we leave OpenRewrite's default (Central).
     */
    private ExecutionContext createContext() {
        ExecutionContext ctx = new InMemoryExecutionContext(
                throwable -> Log.debug("OpenRewrite: %s", Log.describe(throwable)));
        if (credentials == null) {
            return ctx;
        }
        MavenExecutionContextView mavenCtx = MavenExecutionContextView.view(ctx);
        MavenRepository nexusRepo = new MavenRepository(
                "nexus",
                credentials.url(),
                "true",
                "true",
                credentials.username(),
                credentials.password(),
                null);
        mavenCtx.setRepositories(List.of(nexusRepo));
        mavenCtx.setAddCentralRepository(false);
        return ctx;
    }

    private List<SourceFile> parsePom(ExecutionContext ctx, Path pomFile) {
        MavenParser parser = MavenParser.builder().build();
        Parser.Input input = new Parser.Input(pomFile, () -> {
            try {
                return Files.newInputStream(pomFile);
            } catch (IOException e) {
                throw new IllegalStateException("Cannot read " + pomFile, e);
            }
        });
        return parser.parseInputs(List.of(input), pomFile.getParent(), ctx)
                .filter(sf -> !(sf instanceof ParseError))
                .toList();
    }

    /** Runs a recipe and returns the rewritten content, or {@code null} when it changed nothing. */
    private String runRecipe(Recipe recipe, List<SourceFile> docs, ExecutionContext ctx) {
        RecipeRun run = recipe.run(new InMemoryLargeSourceSet(docs), ctx);
        List<Result> results = run.getChangeset().getAllResults();
        if (results.isEmpty()) {
            return null;
        }
        SourceFile updated = results.getFirst().getAfter();
        return updated == null ? null : updated.printAll();
    }

    /**
     * Recipes that move {@code artifact} to {@code newVersion}, tried in order.
     *
     * <p>An artifact of type {@code pom} is either a parent or an imported BOM and lives in a
     * different part of the document than a normal dependency, so both shapes are attempted.
     */
    private List<Recipe> createRecipes(Artifact artifact, String newVersion) {
        if ("pom".equals(artifact.getExtension())) {
            return List.of(
                    // retainVersions "*:*" keeps explicit version overrides already in the POM,
                    // so bumping a parent never silently un-pins something the team pinned.
                    new ChangeParentPom(
                            artifact.getGroupId(), artifact.getGroupId(),
                            artifact.getArtifactId(), artifact.getArtifactId(),
                            newVersion, null, null, null, true, List.of("*:*")),
                    new ChangeDependencyGroupIdAndArtifactId(
                            artifact.getGroupId(), artifact.getArtifactId(),
                            artifact.getGroupId(), artifact.getArtifactId(),
                            newVersion, null, true, true));
        }
        return List.of(
                new UpgradeDependencyVersion(
                        artifact.getGroupId(), artifact.getArtifactId(), newVersion, null, true, null));
    }

    /**
     * Computes the POM content that would result from upgrading {@code artifact}.
     * Returns {@code null} when no recipe produced a change — which usually means the version
     * is controlled somewhere other than this file.
     */
    public String previewUpgrade(File pomFile, Artifact artifact, String newVersion) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePom(ctx, pomFile.toPath());
            for (Recipe recipe : createRecipes(artifact, newVersion)) {
                String result = runRecipe(recipe, docs, ctx);
                if (result != null) {
                    Log.debug("Recipe %s produced a change for %s:%s",
                            recipe.getClass().getSimpleName(), artifact.getArtifactId(), newVersion);
                    return result;
                }
            }
        } catch (Exception e) {
            Log.debug("Upgrade preview failed for %s:%s -> %s: %s",
                    artifact.getGroupId(), artifact.getArtifactId(), newVersion, Log.describe(e));
        }
        return null;
    }

    /**
     * Computes the POM content that would result from pinning {@code groupId:artifactId} in
     * {@code dependencyManagement}.
     *
     * <p>This is the universal lever: Maven gives {@code dependencyManagement} in the current POM
     * precedence over both nearest-wins mediation and any imported BOM, so it can force a version
     * no other edit can reach. It is also the bluntest, which is why the engine reaches for it last.
     */
    public String previewManagedOverride(File pomFile, String groupId, String artifactId, String version) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePom(ctx, pomFile.toPath());

            // An existing managed entry should be updated rather than duplicated.
            String upgraded = runRecipe(
                    new UpgradeDependencyVersion(groupId, artifactId, version, null, true, null), docs, ctx);
            if (upgraded != null) {
                return upgraded;
            }
            return runRecipe(
                    new AddManagedDependency(groupId, artifactId, version,
                            null, null, null, null, null, groupId + ":" + artifactId, null,
                            "pinned by vulnchecker to remediate a known vulnerability"),
                    docs, ctx);
        } catch (Exception e) {
            Log.debug("Managed-override preview failed for %s:%s -> %s: %s",
                    groupId, artifactId, version, Log.describe(e));
        }
        return null;
    }

    /** Writes previously computed content to the POM. */
    public void write(File pomFile, String content) throws IOException {
        Files.writeString(pomFile.toPath(), content);
    }
}
