package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Runs the project's own Maven build and captures its output.
 *
 * <p>Used as ground truth for what a build actually resolves. Enumerating classpaths from the POM
 * always misses something — plugin dependencies, annotation processors, framework augmentation
 * classpaths, and resolvers like Quarkus's that mediate versions independently of the project
 * graph. The build has no such blind spot, and when it fails it names the artifact.
 */
public final class MavenBuildRunner {

    /** Goals that exercise dependency resolution without running tests. */
    public static final String DEFAULT_GOALS = "package -DskipTests";

    public record Result(int exitCode, String output) {

        public boolean succeeded() {
            return exitCode == 0;
        }
    }

    private final Path projectDirectory;

    public MavenBuildRunner(Path projectDirectory) {
        this.projectDirectory = projectDirectory;
    }

    /**
     * Runs {@code mvn -B <goals>} in the project directory.
     *
     * <p>Output is merged and returned rather than streamed: it is scanned for quarantine
     * failures, and forwarding a full Maven log into this tool's own report would bury it.
     */
    public Result run(String goals) {
        List<String> command = new ArrayList<>();
        command.add("mvn");
        command.add("-B");
        command.addAll(List.of(goals.trim().split("\\s+")));

        Log.debug("Running: %s (in %s)", String.join(" ", command), projectDirectory);

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(projectDirectory.toFile());
        processBuilder.redirectErrorStream(true);

        try {
            Process process = processBuilder.start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();
            Log.debug("Build exited with %d (%d bytes of output)", exitCode, output.length());
            return new Result(exitCode, output);

        } catch (IOException e) {
            throw new IllegalStateException(
                    "Could not start Maven. Ensure 'mvn' is on the PATH.", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("The build was interrupted.", e);
        }
    }
}
