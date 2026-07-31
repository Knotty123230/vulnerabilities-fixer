package com.vulncheck;

import org.apache.maven.model.Model;
import org.apache.maven.model.Plugin;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.graph.DependencyNode;
import org.eclipse.aether.graph.DependencyVisitor;

import java.io.File;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.jar.JarFile;

/**
 * Discovers artifacts a build downloads that are <em>not</em> in the project's dependency graph.
 *
 * <p>{@code <dependencies>} describes what the application needs at compile and run time. A build
 * resolves considerably more than that, and anything it resolves can be blocked by a repository
 * firewall — at which point the build fails on a coordinate the dependency graph never mentions.
 *
 * <p>Two such classpaths are covered here:
 * <ul>
 *   <li><b>Maven plugins</b> and their declared dependencies.</li>
 *   <li><b>Quarkus deployment artifacts.</b> Every Quarkus extension jar carries
 *       {@code META-INF/quarkus-extension.properties} naming a {@code deployment-artifact}, and
 *       {@code quarkus-maven-plugin} resolves those plus their transitive dependencies to build the
 *       augmentation classpath. That closure is large and entirely invisible to the runtime graph:
 *       {@code kotlinx-metadata-jvm} arrives this way, which is why a scan of the runtime graph can
 *       report zero quarantined components while {@code mvn install} fails on exactly that.</li>
 * </ul>
 */
public final class BuildTimeArtifacts {

    /** Marker file every Quarkus extension ships. */
    private static final String QUARKUS_EXTENSION_DESCRIPTOR = "META-INF/quarkus-extension.properties";
    private static final String DEPLOYMENT_ARTIFACT_KEY = "deployment-artifact";

    /** An artifact outside the dependency graph, with where it came from. */
    public record BuildArtifact(Artifact artifact, String origin) {
    }

    private final LocalProjectAnalyzer analyzer;
    private final ArtifactAvailability availability;

    public BuildTimeArtifacts(LocalProjectAnalyzer analyzer, ArtifactAvailability availability) {
        this.analyzer = analyzer;
        this.availability = availability;
    }

    /**
     * Everything the build resolves beyond the dependency graph, de-duplicated and excluding
     * artifacts already present in {@code runtimeArtifacts}.
     */
    public List<BuildArtifact> discover(File pomFile, List<Artifact> runtimeArtifacts) {
        Map<String, BuildArtifact> found = new LinkedHashMap<>();

        for (BuildArtifact candidate : discoverPlugins(pomFile)) {
            found.putIfAbsent(key(candidate.artifact()), candidate);
        }
        for (BuildArtifact candidate : discoverQuarkusDeployment(runtimeArtifacts)) {
            found.putIfAbsent(key(candidate.artifact()), candidate);
        }

        runtimeArtifacts.forEach(artifact -> found.remove(key(artifact)));
        return List.copyOf(found.values());
    }

    private static String key(Artifact artifact) {
        return artifact.getGroupId() + ":" + artifact.getArtifactId() + ":" + artifact.getVersion();
    }

    // ------------------------------------------------------------------
    // Maven plugins
    // ------------------------------------------------------------------

    private List<BuildArtifact> discoverPlugins(File pomFile) {
        List<BuildArtifact> plugins = new ArrayList<>();
        try {
            Model model = analyzer.readEffectiveModel(pomFile);
            if (model.getBuild() == null) {
                return plugins;
            }
            for (Plugin plugin : model.getBuild().getPlugins()) {
                if (plugin.getVersion() == null) {
                    // Version comes from a lifecycle default we cannot see here; skip rather
                    // than guess, since probing a wrong version proves nothing.
                    continue;
                }
                plugins.add(new BuildArtifact(new DefaultArtifact(
                        plugin.getGroupId(), plugin.getArtifactId(), "jar", plugin.getVersion()),
                        "maven plugin"));

                plugin.getDependencies().stream()
                        .filter(dependency -> dependency.getVersion() != null)
                        .forEach(dependency -> plugins.add(new BuildArtifact(new DefaultArtifact(
                                dependency.getGroupId(), dependency.getArtifactId(),
                                dependency.getType() == null ? "jar" : dependency.getType(),
                                dependency.getVersion()),
                                "maven plugin dependency")));
            }
        } catch (Exception e) {
            Log.debug("Could not enumerate build plugins: %s", Log.describe(e));
        }
        return plugins;
    }

    // ------------------------------------------------------------------
    // Quarkus augmentation classpath
    // ------------------------------------------------------------------

    private List<BuildArtifact> discoverQuarkusDeployment(List<Artifact> runtimeArtifacts) {
        List<BuildArtifact> deployment = new ArrayList<>();

        for (Artifact runtime : runtimeArtifacts) {
            String coordinate = readDeploymentArtifact(runtime);
            if (coordinate == null) {
                continue;
            }
            Artifact deploymentArtifact = parseCoordinate(coordinate);
            if (deploymentArtifact == null) {
                Log.debug("Unparseable deployment-artifact '%s' in %s", coordinate, runtime);
                continue;
            }

            deployment.add(new BuildArtifact(deploymentArtifact, "Quarkus deployment"));
            // The extension's own deployment module is rarely the problem; its transitive
            // dependencies are, and they are only reachable from here.
            deployment.addAll(expand(deploymentArtifact));
        }

        if (!deployment.isEmpty()) {
            Log.debug("Quarkus augmentation classpath contributes %d artifact(s)", deployment.size());
        }
        return deployment;
    }

    /** Reads {@code deployment-artifact} from an extension jar, or {@code null} if not one. */
    private String readDeploymentArtifact(Artifact runtime) {
        if (!"jar".equals(runtime.getExtension())) {
            return null;
        }
        Path jar = availability.localFile(runtime).orElse(null);
        if (jar == null) {
            return null;
        }
        try (JarFile jarFile = new JarFile(jar.toFile())) {
            var entry = jarFile.getEntry(QUARKUS_EXTENSION_DESCRIPTOR);
            if (entry == null) {
                return null;
            }
            Properties properties = new Properties();
            try (InputStream in = jarFile.getInputStream(entry)) {
                // Properties.load un-escapes the "\:" separators Quarkus writes.
                properties.load(in);
            }
            return properties.getProperty(DEPLOYMENT_ARTIFACT_KEY);
        } catch (Exception e) {
            Log.debug("Could not read the extension descriptor of %s: %s", runtime, e.getMessage());
            return null;
        }
    }

    /** Transitive closure of a deployment artifact. */
    private List<BuildArtifact> expand(Artifact deploymentArtifact) {
        List<BuildArtifact> transitive = new ArrayList<>();
        try {
            DependencyNode root = analyzer.collectFor(deploymentArtifact);
            root.accept(new DependencyVisitor() {
                @Override
                public boolean visitEnter(DependencyNode node) {
                    Artifact artifact = node.getArtifact();
                    if (node != root && artifact != null) {
                        transitive.add(new BuildArtifact(artifact, "Quarkus deployment (transitive)"));
                    }
                    return true;
                }

                @Override
                public boolean visitLeave(DependencyNode node) {
                    return true;
                }
            });
        } catch (Exception e) {
            Log.debug("Could not expand %s: %s", deploymentArtifact, Log.describe(e));
        }
        return transitive;
    }

    static Artifact parseCoordinate(String coordinate) {
        String[] parts = coordinate.trim().split(":");
        if (parts.length < 3) {
            return null;
        }
        return new DefaultArtifact(parts[0], parts[1], "jar", parts[parts.length - 1]);
    }
}
