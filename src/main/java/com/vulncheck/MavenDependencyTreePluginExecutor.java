package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MavenDependencyTreePluginExecutor implements DependencyTreeExecutor {

    @Override
    public Path execute(Path fileWithDeps) {
        Path projectDirectory = fileWithDeps.toAbsolutePath().normalize();
        if (!Files.isDirectory(projectDirectory)) {
            throw new IllegalArgumentException("Maven project directory does not exist: " + projectDirectory);
        }

        Path outputFile = projectDirectory.resolve("target/dependency-tree.json");
        List<String> command = new ArrayList<>();
        command.add("mvn");
        command.add("org.apache.maven.plugins:maven-dependency-plugin:3.7.0:tree");
        command.add("-B");
        command.add("-DoutputType=json");
        command.add("-DoutputFile=" + outputFile);
        command.add("-Dverbose");

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(projectDirectory.toFile());
        pb.redirectErrorStream(true);

        try {
            Process process = pb.start();
            String mavenOutput = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            int exitCode = process.waitFor();

            if (exitCode != 0) {
                throw new IllegalStateException("Maven dependency:tree failed (exit code " + exitCode + "):\n" + mavenOutput);
            }
            if (!Files.isRegularFile(outputFile)) {
                throw new IllegalStateException("Maven completed but did not create: " + outputFile);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Could not start Maven. Ensure 'mvn' is installed and available on PATH.", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Maven dependency:tree was interrupted.", e);
        }

        return outputFile;
    }
}
