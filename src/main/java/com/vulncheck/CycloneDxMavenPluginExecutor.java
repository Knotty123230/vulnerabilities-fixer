package com.vulncheck;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class CycloneDxMavenPluginExecutor implements DependencyTreeExecutor {

    public static final String PLUGIN_MAKE_AGGREGATE_BOM = "org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom";

    @Override
    public Path execute(Path fileWithDeps) {

        System.out.println("Executing CycloneDX Maven Plugin");


        List<String> command = new ArrayList<>();
        command.add("mvn");
        command.add(PLUGIN_MAKE_AGGREGATE_BOM);
        command.add("-DoutputFormat=json");
        command.add("-DoutputName=bom");


        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(fileWithDeps.toFile());
        pb.redirectErrorStream(true);
        Process p = null;
        try {
            p = pb.start();
            p.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return fileWithDeps.resolve("target/bom.json");

    }
}
