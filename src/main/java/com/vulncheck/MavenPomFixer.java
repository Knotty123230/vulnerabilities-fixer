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
import org.openrewrite.maven.RemoveRedundantDependencyVersions;
import org.openrewrite.maven.UpgradeDependencyVersion;
import org.openrewrite.maven.tree.MavenRepository;
import org.openrewrite.tree.ParseError;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        return createContext(null);
    }

    /**
     * @param errorSink when non-null, collects every message OpenRewrite reports through its
     *                  {@code onError} callback during this context's lifetime.
     *
     *                  <p>This callback is a second, independent place recipe failures go missing.
     *                  It fires for problems a recipe treats as non-fatal — most commonly a POM or
     *                  metadata file that could not be downloaded — and the recipe then simply
     *                  produces no change rather than throwing. Without capturing it, "no recipe
     *                  produced a change" is the only thing callers ever see, even when the real
     *                  story is "OpenRewrite could not reach the artifact to verify it exists".
     */
    private ExecutionContext createContext(List<String> errorSink) {
        ExecutionContext ctx = new InMemoryExecutionContext(throwable -> {
            String message = Log.describe(throwable);
            Log.debug("OpenRewrite: %s", message);
            if (errorSink != null) {
                errorSink.add(message);
            }
        });
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

    /** What OpenRewrite is actually configured to talk to — printed once, always visible. */
    public String describeRepository() {
        if (credentials == null) {
            return "Maven Central (no private repository configured for OpenRewrite)";
        }
        return credentials.url() + (credentials.isAuthenticated() ? " (authenticated)" : " (anonymous)");
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
        List<SourceFile> after = applyRecipe(recipe, docs, ctx);
        return after == null ? null : after.getFirst().printAll();
    }

    /** Applies one recipe, returning the new sources or {@code null} when nothing changed. */
    private List<SourceFile> applyRecipe(Recipe recipe, List<SourceFile> docs, ExecutionContext ctx) {
        RecipeRun run = recipe.run(new InMemoryLargeSourceSet(docs), ctx);
        List<Result> results = run.getChangeset().getAllResults();
        if (results.isEmpty()) {
            return null;
        }
        SourceFile updated = results.getFirst().getAfter();
        return updated == null ? null : List.of(updated);
    }

    /**
     * Runs recipes in sequence, feeding each one the output of the last.
     *
     * <p>The intermediate document is kept in memory rather than round-tripped through a file, so
     * the Maven model OpenRewrite attaches to the source survives between steps — the later recipe
     * needs it to know what the earlier one made managed.
     *
     * @return the final content, or {@code null} when no recipe in the chain changed anything
     */
    private String runRecipeChain(List<Recipe> recipes, List<SourceFile> docs, ExecutionContext ctx) {
        List<SourceFile> current = docs;
        boolean changed = false;

        for (Recipe recipe : recipes) {
            List<SourceFile> after = applyRecipe(recipe, current, ctx);
            if (after != null) {
                current = after;
                changed = true;
            }
        }
        return changed ? current.getFirst().printAll() : null;
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
        return previewManagedOverride(pomFile, groupId, artifactId, version, true);
    }

    /**
     * @param onlyIfUsed when {@code true}, the managed entry is added only if the artifact is
     *                   already somewhere in the project's dependency graph. That guard is right
     *                   for a vulnerability pin — managing something the project never resolves is
     *                   dead configuration — but wrong for an artifact the <em>build</em> pulls in
     *                   outside the graph, such as a Quarkus deployment dependency. There the guard
     *                   silently rejects the only edit that can unblock the build.
     */
    public String previewManagedOverride(File pomFile, String groupId, String artifactId, String version,
                                         boolean onlyIfUsed) {
        return previewManagedOverrideDetailed(pomFile, groupId, artifactId, version, onlyIfUsed).content();
    }

    /** Outcome of {@link #previewManagedOverrideDetailed}: the rewritten POM, or why there is none. */
    public record OverridePreview(String content, String failureReason) {
        public boolean succeeded() {
            return content != null;
        }
    }

    /**
     * Same as {@link #previewManagedOverride}, but reports <em>why</em> nothing changed instead of a
     * bare {@code null}.
     *
     * <p>A quarantined artifact this method cannot pin is one whose only remaining fix is a firewall
     * waiver, not another version — that is a real, actionable conclusion, and the reason it could
     * not be pinned belongs in the report a person actually reads, not only behind {@code --verbose}.
     * Silently losing it here is exactly what turned one blocked build into several rounds of
     * guessing.
     */
    public OverridePreview previewManagedOverrideDetailed(File pomFile, String groupId, String artifactId,
                                                           String version, boolean onlyIfUsed) {
        List<String> recipeErrors = new ArrayList<>();
        try {
            ExecutionContext ctx = createContext(recipeErrors);
            List<SourceFile> docs = parsePom(ctx, pomFile.toPath());

            // An existing managed entry should be updated rather than duplicated.
            String upgraded = runRecipe(
                    new UpgradeDependencyVersion(groupId, artifactId, version, null, true, null), docs, ctx);
            if (upgraded != null) {
                return new OverridePreview(upgraded, null);
            }

            // UpgradeDependencyVersion only ever moves a version forward, so a declared dependency
            // that has to move *back* — the case when the quarantined release is also the newest
            // one published — needs a recipe that simply sets the version.
            String changed = runRecipe(
                    new ChangeDependencyGroupIdAndArtifactId(
                            groupId, artifactId, groupId, artifactId, version, null, true, true),
                    docs, ctx);
            if (changed != null) {
                return new OverridePreview(changed, null);
            }

            String added = runRecipe(
                    new AddManagedDependency(groupId, artifactId, version,
                            null, null, null, null, null,
                            onlyIfUsed ? groupId + ":" + artifactId : null, null,
                            "pinned by vulnchecker"),
                    docs, ctx);
            if (added != null) {
                return new OverridePreview(added, null);
            }

            // Last resort, and only when the caller explicitly wants an unconditional pin.
            // OpenRewrite's Maven recipes reason about the project's OWN resolved dependency
            // model; an artifact that exists only in a separate resolver's universe — Quarkus's
            // bootstrap resolver building its augmentation classpath is exactly this case — is
            // invisible to that model even with the repository correctly configured, and
            // AddManagedDependency can then decide there is nothing to do without raising any
            // error at all. There is no recipe-level lever left at that point, so the entry is
            // written by direct model manipulation instead.
            if (!onlyIfUsed) {
                String raw = addOrUpdateManagedDependencyRaw(pomFile, groupId, artifactId, version);
                if (raw != null) {
                    return new OverridePreview(raw, null);
                }
            }

            return new OverridePreview(null, describeNoChange(recipeErrors, groupId, artifactId, version));

        } catch (Exception e) {
            // Visible without --verbose: an artifact this fails for has no other route to a fix,
            // and burying the reason behind a debug flag is what cost real time diagnosing this.
            Log.warn("Managed-override preview failed for %s:%s -> %s: %s",
                    groupId, artifactId, version, Log.describe(e));
            return new OverridePreview(null, "recipe execution threw: " + Log.describe(e));
        }
    }

    /**
     * Adds or updates a {@code dependencyManagement} entry by editing the raw Maven model,
     * bypassing OpenRewrite's recipe engine entirely.
     *
     * <p>This is deliberately a text-level edit, not a parse-model-and-reserialize round trip.
     * A model-based writer (e.g. {@code MavenXpp3Writer}) reconstructs the <em>entire</em> document
     * from its in-memory model — reordering elements to schema order, losing comments, and
     * reformatting whitespace throughout. For a change that should be five inserted lines, that
     * turns the diff into the whole file, which is unreviewable and defeats the purpose of a
     * targeted fix. Everything outside the touched dependency (or the inserted block) is copied
     * through byte-for-byte.
     */
    /* package */ String addOrUpdateManagedDependencyRaw(File pomFile, String groupId, String artifactId,
                                                          String version) {
        try {
            String original = Files.readString(pomFile.toPath(), StandardCharsets.UTF_8);
            String lineEnding = original.contains("\r\n") ? "\r\n" : "\n";

            Matcher dmMatcher = DEPENDENCY_MANAGEMENT_BLOCK.matcher(original);
            if (dmMatcher.find()) {
                String updatedBlock = updateOrInsertInManagementBlock(
                        dmMatcher.group(0), groupId, artifactId, version, lineEnding);
                if (updatedBlock == null) {
                    return null;
                }
                return original.substring(0, dmMatcher.start())
                        + updatedBlock
                        + original.substring(dmMatcher.end());
            }

            int insertionPoint = findInsertionPointForNewManagementBlock(original);
            if (insertionPoint < 0) {
                return null;
            }
            String indent = detectIndent(original);
            String newBlock = buildManagementBlock(groupId, artifactId, version, indent, lineEnding);
            return original.substring(0, insertionPoint) + newBlock + original.substring(insertionPoint);

        } catch (Exception e) {
            Log.warn("Raw managed-dependency fallback failed for %s:%s -> %s: %s",
                    groupId, artifactId, version, Log.describe(e));
            return null;
        }
    }

    private static final Pattern DEPENDENCY_MANAGEMENT_BLOCK = Pattern.compile(
            "[ \\t]*<dependencyManagement>.*?</dependencyManagement>[ \\t]*\\R?", Pattern.DOTALL);

    /**
     * Edits an existing {@code <dependencyManagement>} block: updates the {@code <version>} in
     * place if {@code groupId:artifactId} is already managed there, otherwise inserts a new
     * {@code <dependency>} entry right after the block's {@code <dependencies>} tag.
     *
     * @return the rewritten block, or {@code null} if the block has no {@code <dependencies>} child
     *         to anchor an insertion to (malformed enough that guessing would be unsafe)
     */
    private static String updateOrInsertInManagementBlock(String dmBlock, String groupId, String artifactId,
                                                           String version, String lineEnding) {
        Pattern existingDependency = Pattern.compile(
                "[ \\t]*<dependency>\\s*"
                        + "<groupId>\\s*" + Pattern.quote(groupId) + "\\s*</groupId>\\s*"
                        + "<artifactId>\\s*" + Pattern.quote(artifactId) + "\\s*</artifactId>\\s*"
                        + "<version>[^<]*</version>.*?</dependency>[ \\t]*\\R?",
                Pattern.DOTALL);
        Matcher existing = existingDependency.matcher(dmBlock);
        if (existing.find()) {
            String updated = existing.group(0).replaceFirst(
                    "<version>[^<]*</version>",
                    Matcher.quoteReplacement("<version>" + version + "</version>"));
            return dmBlock.substring(0, existing.start()) + updated + dmBlock.substring(existing.end());
        }

        Matcher dependenciesOpen = Pattern.compile("<dependencies>\\s*\\R?").matcher(dmBlock);
        if (!dependenciesOpen.find()) {
            return null;
        }
        String indent = detectEntryIndent(dmBlock, dependenciesOpen.end());
        String snippet = dependencyElement(groupId, artifactId, version, indent, lineEnding);
        return dmBlock.substring(0, dependenciesOpen.end()) + snippet + dmBlock.substring(dependenciesOpen.end());
    }

    /** Indentation copied from the next sibling element, or a sensible default if there is none. */
    private static String detectEntryIndent(String block, int searchFrom) {
        Matcher indentOfNextTag = Pattern.compile("\\R([ \\t]*)<").matcher(block);
        if (indentOfNextTag.find(searchFrom)) {
            return indentOfNextTag.group(1);
        }
        return "      ";
    }

    /** Indentation used by the first indented element in the document, or a two-space default. */
    private static String detectIndent(String pom) {
        Matcher m = Pattern.compile("(?m)^([ \\t]+)<\\w").matcher(pom);
        return m.find() ? m.group(1) : "  ";
    }

    /**
     * Where to insert a brand-new {@code <dependencyManagement>} when the POM has none: right
     * before the project's own {@code <dependencies>}, matching where a person would put it, or
     * failing that just before {@code </project>}.
     */
    private static int findInsertionPointForNewManagementBlock(String pom) {
        Matcher dependencies = Pattern.compile("(?m)^[ \\t]*<dependencies>").matcher(pom);
        if (dependencies.find()) {
            return dependencies.start();
        }
        Matcher properties = Pattern.compile("</properties>\\s*\\R").matcher(pom);
        if (properties.find()) {
            return properties.end();
        }
        int idx = pom.lastIndexOf("</project>");
        return idx < 0 ? -1 : idx;
    }

    private static String buildManagementBlock(String groupId, String artifactId, String version,
                                                String indent, String lineEnding) {
        return indent + "<dependencyManagement>" + lineEnding
                + indent + "  <dependencies>" + lineEnding
                + dependencyElement(groupId, artifactId, version, indent + "    ", lineEnding)
                + indent + "  </dependencies>" + lineEnding
                + indent + "</dependencyManagement>" + lineEnding;
    }

    private static String dependencyElement(String groupId, String artifactId, String version,
                                            String indent, String lineEnding) {
        return indent + "<dependency>" + lineEnding
                + indent + "  <groupId>" + groupId + "</groupId>" + lineEnding
                + indent + "  <artifactId>" + artifactId + "</artifactId>" + lineEnding
                + indent + "  <version>" + version + "</version>" + lineEnding
                + indent + "</dependency>" + lineEnding;
    }

    /** Explains a silent no-op, using whatever OpenRewrite itself reported along the way. */
    private String describeNoChange(List<String> recipeErrors, String groupId, String artifactId, String version) {
        if (!recipeErrors.isEmpty()) {
            String detail = recipeErrors.stream().distinct().limit(3).reduce((a, b) -> a + " | " + b).orElse("");
            Log.warn("OpenRewrite reported %d error(s) computing an edit for %s:%s -> %s: %s",
                    recipeErrors.size(), groupId, artifactId, version, detail);
            return "OpenRewrite could not compute the edit against " + describeRepository() + ": " + detail;
        }
        return "no recipe (upgrade, change-version, or add-managed-dependency) produced a change against "
                + describeRepository() + "; the artifact may already be pinned to this exact version "
                + "elsewhere in a way these recipes cannot see, or the POM's structure is blocking the edit";
    }

    /**
     * Computes the POM content that would result from importing {@code bomGroupId:bomArtifactId}
     * and dropping the now-redundant explicit versions of {@code dependencyGroupId}'s artifacts.
     *
     * <p>Two recipes, in this order and for a reason. The import alone would leave every existing
     * {@code <version>} in place, and those win over an imported BOM — the family would stay
     * skewed and the diff would suggest otherwise. So
     * {@code RemoveRedundantDependencyVersions} follows to strip them.
     *
     * <p>It runs with {@code GTE} rather than the default {@code EQ}: {@code EQ} only removes a
     * version identical to the managed one, which is exactly the case that was never the problem.
     * {@code GTE} removes an explicit version whenever the BOM pins the same or newer, which is
     * what makes stragglers actually move up.
     *
     * <p>A property-driven version leaves its {@code <property>} behind — OpenRewrite does not
     * clean those up yet (openrewrite/rewrite#4350). Harmless, but it shows up in the diff.
     */
    public String previewBomImport(File pomFile, String bomGroupId, String bomArtifactId, String version,
                                   String dependencyGroupId) {
        try {
            ExecutionContext ctx = createContext();
            List<SourceFile> docs = parsePom(ctx, pomFile.toPath());

            return runRecipeChain(List.of(
                    new AddManagedDependency(
                            bomGroupId, bomArtifactId, version,
                            "import", "pom", null, null, null,
                            dependencyGroupId + ":*", null,
                            "imported by vulnchecker to keep " + dependencyGroupId + " artifacts on one version"),
                    new RemoveRedundantDependencyVersions(
                            dependencyGroupId, "*",
                            RemoveRedundantDependencyVersions.Comparator.GTE, null)
            ), docs, ctx);

        } catch (Exception e) {
            Log.debug("BOM import preview failed for %s:%s:%s: %s",
                    bomGroupId, bomArtifactId, version, Log.describe(e));
        }
        return null;
    }

    /** Writes previously computed content to the POM. */
    public void write(File pomFile, String content) throws IOException {
        Files.writeString(pomFile.toPath(), content);
    }
}
