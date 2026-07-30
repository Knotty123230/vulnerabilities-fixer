package com.vulncheck;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.apache.maven.model.Model;
import org.apache.maven.model.building.DefaultModelBuilderFactory;
import org.apache.maven.model.building.DefaultModelBuildingRequest;
import org.apache.maven.model.building.ModelBuilder;
import org.apache.maven.model.building.ModelBuildingException;
import org.apache.maven.model.building.ModelBuildingRequest;
import org.apache.maven.model.building.ModelBuildingResult;
import org.apache.maven.model.building.ModelProblem;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.collection.CollectRequest;
import org.eclipse.aether.collection.CollectResult;
import org.eclipse.aether.collection.DependencyCollectionException;
import org.eclipse.aether.graph.Dependency;
import org.eclipse.aether.graph.DependencyFilter;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.DependencyVisitor;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactDescriptorException;
import org.eclipse.aether.resolution.ArtifactDescriptorRequest;
import org.eclipse.aether.resolution.ArtifactDescriptorResult;
import org.eclipse.aether.resolution.DependencyRequest;
import org.eclipse.aether.resolution.DependencyResolutionException;
import org.eclipse.aether.resolution.DependencyResult;
import org.eclipse.aether.util.artifact.JavaScopes;
import org.eclipse.aether.util.filter.DependencyFilterUtils;

/**
 * Reads a Maven project and answers the two questions the remediation engine needs:
 * <em>what does the resolved dependency graph actually look like</em>, and
 * <em>where is a given version controlled from</em>.
 */
public class LocalProjectAnalyzer {

    private final RepositorySystem repositorySystem;
    private final RepositorySystemSession repositorySystemSession;
    private final List<RemoteRepository> repositories;

    /** Raw (un-interpolated) POMs, keyed by canonical path. Re-parsing per query added up. */
    private final Map<String, Model> rawModelCache = new ConcurrentHashMap<>();

    public LocalProjectAnalyzer(final RepositorySystem repositorySystem,
                                final RepositorySystemSession repositorySystemSession,
                                final List<RemoteRepository> repositories) {
        this.repositorySystem = repositorySystem;
        this.repositorySystemSession = repositorySystemSession;
        this.repositories = List.copyOf(repositories);
    }

    // ------------------------------------------------------------------
    // Raw model access
    // ------------------------------------------------------------------

    /**
     * Parses the POM exactly as written — no inheritance, no interpolation. This is what we
     * need to decide <em>where an edit belongs</em>, as opposed to what Maven ends up resolving.
     */
    public Model readRawModel(final File pomFile) throws IOException, XmlPullParserException {
        String key = pomFile.getCanonicalPath();
        Model cached = rawModelCache.get(key);
        if (cached != null) {
            return cached;
        }
        final MavenXpp3Reader reader = new MavenXpp3Reader();
        try (Reader in = Files.newBufferedReader(pomFile.toPath(), StandardCharsets.UTF_8)) {
            Model model = reader.read(in);
            rawModelCache.put(key, model);
            return model;
        }
    }

    /** Drops cached parses — call after the POM on disk has been rewritten. */
    public void invalidate(final File pomFile) {
        try {
            rawModelCache.remove(pomFile.getCanonicalPath());
        } catch (IOException ignored) {
            rawModelCache.clear();
        }
    }

    public Artifact getParentCandidate(final File pomFile) throws IOException, XmlPullParserException {
        final Model rawModel = readRawModel(pomFile);
        if (rawModel.getParent() == null) {
            return null;
        }
        return new DefaultArtifact(
                rawModel.getParent().getGroupId(),
                rawModel.getParent().getArtifactId(),
                null,
                "pom",
                rawModel.getParent().getVersion());
    }

    // ------------------------------------------------------------------
    // Version-control-point detection
    // ------------------------------------------------------------------

    public enum UpdateStrategy {
        /** Version literal sits in this POM (in {@code <dependencies>} or local {@code <dependencyManagement>}). */
        EXPLICIT_VERSION,
        /** Version comes from a {@code ${property}} that this POM defines. */
        MANAGED_BY_PROPERTY,
        /** Version comes from an imported BOM. */
        MANAGED_BY_BOM,
        /** Version comes from the parent POM's dependencyManagement. */
        MANAGED_BY_PARENT,
        /** The artifact is not declared here at all — it is purely transitive. */
        TRANSITIVE_ONLY
    }

    /**
     * Locates the control point for {@code groupId:artifactId} in {@code pomFile}.
     *
     * <p>Order matters and follows Maven's own precedence: a version in this POM's
     * {@code dependencyManagement} beats an imported BOM, which beats the parent.
     */
    public UpdateStrategy determineUpdateStrategy(final File pomFile, final String groupId, final String artifactId)
            throws IOException, XmlPullParserException {
        final Model rawModel = readRawModel(pomFile);

        final Optional<org.apache.maven.model.Dependency> declared = rawModel.getDependencies().stream()
                .filter(d -> matches(d, groupId, artifactId))
                .findFirst();

        if (declared.isPresent() && declared.get().getVersion() != null) {
            return isPropertyReference(declared.get().getVersion())
                    ? UpdateStrategy.MANAGED_BY_PROPERTY
                    : UpdateStrategy.EXPLICIT_VERSION;
        }

        if (rawModel.getDependencyManagement() != null) {
            final List<org.apache.maven.model.Dependency> managed =
                    rawModel.getDependencyManagement().getDependencies();

            final Optional<org.apache.maven.model.Dependency> managedHere = managed.stream()
                    .filter(d -> !isBomImport(d))
                    .filter(d -> matches(d, groupId, artifactId))
                    .findFirst();
            if (managedHere.isPresent()) {
                return isPropertyReference(managedHere.get().getVersion())
                        ? UpdateStrategy.MANAGED_BY_PROPERTY
                        : UpdateStrategy.EXPLICIT_VERSION;
            }

            if (managed.stream().anyMatch(LocalProjectAnalyzer::isBomImport)) {
                return UpdateStrategy.MANAGED_BY_BOM;
            }
        }

        if (rawModel.getParent() != null) {
            return UpdateStrategy.MANAGED_BY_PARENT;
        }

        // Declared with no version and nothing to inherit from would be an invalid POM;
        // in practice this branch means "we never saw it here", which is a fine answer.
        return UpdateStrategy.TRANSITIVE_ONLY;
    }

    private static boolean matches(final org.apache.maven.model.Dependency dependency,
                                   final String groupId, final String artifactId) {
        return groupId.equals(dependency.getGroupId()) && artifactId.equals(dependency.getArtifactId());
    }

    private static boolean isBomImport(final org.apache.maven.model.Dependency dependency) {
        return "pom".equals(dependency.getType()) && "import".equals(dependency.getScope());
    }

    private static boolean isPropertyReference(final String version) {
        return version != null && version.startsWith("${") && version.endsWith("}");
    }

    /**
     * Finds the imported BOM in this POM's {@code dependencyManagement} that manages
     * {@code targetDependency}, by reading each BOM's descriptor.
     *
     * <p>BOMs are checked in declaration order because that is the order Maven itself
     * applies when two imports manage the same artifact — first import wins.
     */
    public org.apache.maven.model.Dependency findBomManagingDependency(final File pomFile,
                                                                       final Artifact targetDependency)
            throws IOException, XmlPullParserException {
        final Model rawModel = readRawModel(pomFile);
        if (rawModel.getDependencyManagement() == null) {
            return null;
        }

        final List<org.apache.maven.model.Dependency> importedBoms = rawModel.getDependencyManagement()
                .getDependencies().stream()
                .filter(LocalProjectAnalyzer::isBomImport)
                .toList();

        for (final org.apache.maven.model.Dependency bom : importedBoms) {
            final String bomVersion = resolveVersionProperty(bom.getVersion(), rawModel);
            if (isPropertyReference(bomVersion)) {
                Log.debug("BOM %s:%s version property %s is not defined in this POM; skipping",
                        bom.getGroupId(), bom.getArtifactId(), bom.getVersion());
                continue;
            }

            final Artifact bomArtifact = new DefaultArtifact(bom.getGroupId(), bom.getArtifactId(), "pom", bomVersion);
            final ArtifactDescriptorRequest descriptorRequest =
                    new ArtifactDescriptorRequest(bomArtifact, repositories, null);

            try {
                final ArtifactDescriptorResult descriptorResult =
                        repositorySystem.readArtifactDescriptor(repositorySystemSession, descriptorRequest);

                final boolean managesTarget = descriptorResult.getManagedDependencies().stream()
                        .anyMatch(managed -> managed.getArtifact().getGroupId().equals(targetDependency.getGroupId())
                                && managed.getArtifact().getArtifactId().equals(targetDependency.getArtifactId()));

                if (managesTarget) {
                    // Return a copy carrying the resolved version, so callers do not have to
                    // re-interpolate ${...} themselves.
                    org.apache.maven.model.Dependency resolved = bom.clone();
                    resolved.setVersion(bomVersion);
                    return resolved;
                }
            } catch (final ArtifactDescriptorException e) {
                Log.debug("Could not read BOM descriptor %s: %s", bomArtifact, e.getMessage());
            }
        }

        return null;
    }

    /** Resolves {@code ${prop}} against this POM's own {@code <properties>}. */
    private String resolveVersionProperty(final String version, final Model rawModel) {
        if (isPropertyReference(version)) {
            final String propertyName = version.substring(2, version.length() - 1);
            return rawModel.getProperties().getProperty(propertyName, version);
        }
        return version;
    }

    /** The property name a dependency's version points at, or {@code null} if it is a literal. */
    public String findVersionProperty(final File pomFile, final String groupId, final String artifactId)
            throws IOException, XmlPullParserException {
        final Model rawModel = readRawModel(pomFile);

        List<org.apache.maven.model.Dependency> all = new ArrayList<>(rawModel.getDependencies());
        if (rawModel.getDependencyManagement() != null) {
            all.addAll(rawModel.getDependencyManagement().getDependencies());
        }
        return all.stream()
                .filter(d -> matches(d, groupId, artifactId))
                .map(org.apache.maven.model.Dependency::getVersion)
                .filter(LocalProjectAnalyzer::isPropertyReference)
                .map(v -> v.substring(2, v.length() - 1))
                .findFirst()
                .orElse(null);
    }

    // ------------------------------------------------------------------
    // Dependency graph
    // ------------------------------------------------------------------

    /**
     * Builds the transitive dependency graph the way Maven would, from the effective model.
     *
     * <p>Two things here are easy to get wrong and both invalidate every downstream verdict:
     * <ul>
     *   <li>{@code dependencyManagement} must be handed to the {@link CollectRequest}. It takes
     *       precedence over nearest-wins mediation, so a graph collected without it reports
     *       versions Maven would never actually resolve — including "still vulnerable" for a
     *       version the BOM pins to something safe.</li>
     *   <li>The root artifact must be set, otherwise the root node carries no coordinates and
     *       path-based reasoning about direct dependencies is off by one.</li>
     * </ul>
     */
    public DependencyNode buildGraphFromPom(final File pomFile)
            throws ModelBuildingException, DependencyCollectionException {
        final Model effectiveModel = buildEffectiveModel(pomFile);

        final List<Dependency> dependencies = effectiveModel.getDependencies().stream()
                .map(LocalProjectAnalyzer::toAetherDependency)
                .toList();

        final List<Dependency> managedDependencies = effectiveModel.getDependencyManagement() == null
                ? List.of()
                : effectiveModel.getDependencyManagement().getDependencies().stream()
                        .map(LocalProjectAnalyzer::toAetherDependency)
                        .toList();

        final CollectRequest collectRequest = new CollectRequest();
        collectRequest.setRootArtifact(new DefaultArtifact(
                effectiveModel.getGroupId(),
                effectiveModel.getArtifactId(),
                "pom",
                effectiveModel.getVersion()));
        collectRequest.setDependencies(dependencies);
        collectRequest.setManagedDependencies(managedDependencies);
        collectRequest.setRepositories(repositories);

        final CollectResult collectResult =
                repositorySystem.collectDependencies(repositorySystemSession, collectRequest);

        for (Exception exception : collectResult.getExceptions()) {
            Log.debug("Graph collection warning: %s", Log.describe(exception));
        }

        return collectResult.getRoot();
    }

    private Model buildEffectiveModel(final File pomFile) throws ModelBuildingException {
        final ModelBuilder modelBuilder = new DefaultModelBuilderFactory().newInstance();
        final DefaultModelBuildingRequest request = new DefaultModelBuildingRequest();
        request.setPomFile(pomFile);
        request.setSystemProperties(System.getProperties());
        request.setValidationLevel(ModelBuildingRequest.VALIDATION_LEVEL_MINIMAL);
        // Plugin resolution is irrelevant to dependency analysis and only costs network round-trips.
        request.setProcessPlugins(false);
        request.setTwoPhaseBuilding(false);
        request.setModelResolver(new AetherModelResolver(repositorySystem, repositorySystemSession, repositories));

        final ModelBuildingResult result = modelBuilder.build(request);
        for (ModelProblem problem : result.getProblems()) {
            Log.debug("Model problem [%s] %s", problem.getSeverity(), problem.getMessage());
        }
        return result.getEffectiveModel();
    }

    /**
     * Downloads the JARs for the compile+runtime classpath and returns the graph with
     * {@code getArtifact().getFile()} populated.
     *
     * <p>Collection alone never sets files, so any bytecode analysis performed on a merely
     * collected graph silently sees an empty classpath.
     */
    public DependencyNode resolveArtifacts(final DependencyNode collectedRoot) throws DependencyResolutionException {
        final DependencyFilter scopeFilter =
                DependencyFilterUtils.classpathFilter(JavaScopes.COMPILE, JavaScopes.RUNTIME);

        final DependencyRequest dependencyRequest = new DependencyRequest(collectedRoot, scopeFilter);
        final DependencyResult result =
                repositorySystem.resolveDependencies(repositorySystemSession, dependencyRequest);

        result.getCollectExceptions().forEach(e -> Log.debug("Resolution warning: %s", Log.describe(e)));
        return result.getRoot();
    }

    private static Dependency toAetherDependency(final org.apache.maven.model.Dependency d) {
        final Artifact artifact = new DefaultArtifact(
                d.getGroupId(), d.getArtifactId(), d.getClassifier(),
                d.getType() == null ? "jar" : d.getType(),
                d.getVersion());
        return new Dependency(artifact, d.getScope(), d.isOptional());
    }

    // ------------------------------------------------------------------
    // Graph queries
    // ------------------------------------------------------------------

    /** One route from the project root down to a matching artifact. */
    public record GraphPath(List<Artifact> nodes) {

        public Artifact directDependency() {
            return nodes.isEmpty() ? null : nodes.getFirst();
        }

        public Artifact target() {
            return nodes.isEmpty() ? null : nodes.getLast();
        }

        public int depth() {
            return nodes.size();
        }

        public boolean isDirect() {
            return nodes.size() == 1;
        }

        /** {@code group:artifact:1.0 -> group:other:2.0} */
        public String render() {
            return nodes.stream()
                    .map(a -> a.getGroupId() + ":" + a.getArtifactId() + ":" + a.getVersion())
                    .reduce((left, right) -> left + " -> " + right)
                    .orElse("");
        }
    }

    /**
     * Collects every route from the project to {@code groupId:artifactId}, shortest first.
     *
     * <p>All routes matter: a vulnerable library reachable through three different direct
     * dependencies needs all three considered, and reporting only one hides why a fix
     * "did not take". The shortest route is the one Maven mediates in favour of, so it is
     * the natural first candidate for an edit.
     */
    public List<GraphPath> findPathsTo(final DependencyNode rootNode, final String groupId, final String artifactId) {
        final List<GraphPath> paths = new ArrayList<>();
        final List<Artifact> currentPath = new ArrayList<>();

        rootNode.accept(new DependencyVisitor() {
            @Override
            public boolean visitEnter(final DependencyNode node) {
                final Artifact artifact = node.getArtifact();
                // The root carries the project itself; it is not part of any dependency path.
                if (node != rootNode && artifact != null) {
                    currentPath.add(artifact);
                    if (artifact.getGroupId().equals(groupId) && artifact.getArtifactId().equals(artifactId)) {
                        paths.add(new GraphPath(List.copyOf(currentPath)));
                    }
                }
                return true;
            }

            @Override
            public boolean visitLeave(final DependencyNode node) {
                if (node != rootNode && node.getArtifact() != null && !currentPath.isEmpty()) {
                    currentPath.removeLast();
                }
                return true;
            }
        });

        return paths.stream()
                .sorted(Comparator.comparingInt(GraphPath::depth))
                .toList();
    }

    /**
     * The direct dependency that should be edited to move {@code groupId:artifactId}.
     * Returns {@code null} when the artifact is absent from the graph.
     */
    public Artifact findDirectDependencyForVulnerability(final DependencyNode rootNode, final String groupId,
                                                         final String artifactId) {
        final List<GraphPath> paths = findPathsTo(rootNode, groupId, artifactId);
        return paths.isEmpty() ? null : paths.getFirst().directDependency();
    }

    /** The version Maven actually resolves for {@code groupId:artifactId}, or {@code null}. */
    public String resolvedVersionOf(final DependencyNode rootNode, final String groupId, final String artifactId) {
        final List<GraphPath> paths = findPathsTo(rootNode, groupId, artifactId);
        return paths.isEmpty() ? null : paths.getFirst().target().getVersion();
    }
}
