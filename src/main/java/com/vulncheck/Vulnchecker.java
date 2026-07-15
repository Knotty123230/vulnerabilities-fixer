package com.vulncheck;

import picocli.CommandLine;

import java.nio.file.Path;
import java.util.Optional;

@CommandLine.Command(name = "vulnchecker", mixinStandardHelpOptions = true, version = "vulnchecker 1.0", description = "A tool to check for vulnerabilities in Java code.")
public class Vulnchecker implements Runnable {


    @CommandLine.Option(names = {"-f", "--file"}, description = "The path to the Java file to check for vulnerabilities.", required = true)
    private Path filePath;

    @CommandLine.Option(names = "--nexus-url", description = "Nexus repository URL.")
    private String nexusUrl;

    @CommandLine.Option(names = "--nexus-username", description = "Nexus username.")
    private String nexusUsername;

    @CommandLine.Option(
            names = "--nexus-password",
            arity = "0..1",
            interactive = true,
            description = "Nexus password. When supplied without a value, prompts without echo."
    )
    private String nexusPassword;

    @CommandLine.Option(
            names = "--save-nexus-credentials",
            description = "Save URL and username in ~/.vulnchecker and the password in macOS Keychain."
    )
    private boolean saveNexusCredentials;

    @CommandLine.Option(names = "--scan-sonatype", description = "Run a Sonatype Lifecycle scan after the Nexus version check.")
    private boolean scanSonatype;

    @CommandLine.Option(names = "--sonatype-url", description = "Sonatype Lifecycle server URL.")
    private String sonatypeUrl;

    @CommandLine.Option(names = "--sonatype-application-id", description = "Sonatype Lifecycle application ID.")
    private String sonatypeApplicationId;

    @CommandLine.Option(names = "--sonatype-username", description = "Sonatype Lifecycle username.")
    private String sonatypeUsername;

    @CommandLine.Option(
            names = "--sonatype-password",
            arity = "0..1",
            interactive = true,
            description = "Sonatype Lifecycle password. When supplied without a value, prompts without echo."
    )
    private String sonatypePassword;

    @CommandLine.Option(
            names = "--save-sonatype-credentials",
            description = "Save Sonatype URL, application ID and username in ~/.vulnchecker; save the password in macOS Keychain."
    )
    private boolean saveSonatypeCredentials;


    public static void main(String[] args) {
        int exitCode = new CommandLine(new Vulnchecker()).execute(args);
        System.exit(exitCode);
    }


    @Override
    public void run() {
        System.out.println("Vulnchecker is running...");
        System.out.println("File: " + filePath.toAbsolutePath().normalize());
        NexusCredentials credentials = resolveNexusCredentials();

        var repositorySystem = MavenResolverFactory.createRepositorySystem();
        NexusVersionResolver nexusVersionResolver = new NexusVersionResolver(repositorySystem, MavenResolverFactory.createSession(repositorySystem, Path.of(
                System.getProperty("user.home"),
                ".m2",
                "repository"
        )),
                credentials.url(),
                credentials.username(),
                credentials.password());

        nexusVersionResolver.getNewerVersions("org.apache.commons", "commons-lang3", "3.12.0").forEach(version -> {
            System.out.println("Newer version available: " + version);
        });

        if (scanSonatype) {
            new SonatypeProcessor(resolveSonatypeCredentials()).scan(filePath);
        }

//        var path = new MavenDependencyTreePluginExecutor().execute(filePath);
//        System.out.println("Dependency tree JSON: " + path);
//        DependencyTreeConverter converter = new DependencyTreeConverter();
//
//        DependencyNode dependencyNode = converter.convert(path);


    }

    private NexusCredentials resolveNexusCredentials() {
        NexusCredentialsStore store = new NexusCredentialsStore();
        Optional<NexusCredentialsStore.NexusSettings> savedSettings = store.loadSettings();

        String url = firstNonBlank(nexusUrl, savedSettings.map(NexusCredentialsStore.NexusSettings::url).orElse(null));
        String username = firstNonBlank(nexusUsername, savedSettings.map(NexusCredentialsStore.NexusSettings::username).orElse(null));
        String password = firstNonBlank(
                nexusPassword,
                System.getenv("VULNCHECKER_NEXUS_PASSWORD"),
                username == null ? null : store.loadPassword(username).orElse(null)
        );

        NexusCredentials credentials = new NexusCredentials(url, username, password);
        if (saveNexusCredentials) {
            store.save(credentials);
        }
        return credentials;
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private SonatypeCredentials resolveSonatypeCredentials() {
        SonatypeCredentialsStore store = new SonatypeCredentialsStore();
        Optional<SonatypeCredentialsStore.SonatypeSettings> savedSettings = store.loadSettings();

        String url = firstNonBlank(sonatypeUrl, savedSettings.map(SonatypeCredentialsStore.SonatypeSettings::serverUrl).orElse(null));
        String applicationId = firstNonBlank(
                sonatypeApplicationId,
                savedSettings.map(SonatypeCredentialsStore.SonatypeSettings::applicationId).orElse(null)
        );
        String username = firstNonBlank(
                sonatypeUsername,
                savedSettings.map(SonatypeCredentialsStore.SonatypeSettings::username).orElse(null)
        );
        String password = firstNonBlank(
                sonatypePassword,
                System.getenv("VULNCHECKER_SONATYPE_PASSWORD"),
                username == null ? null : store.loadPassword(username).orElse(null)
        );

        SonatypeCredentials credentials = new SonatypeCredentials(url, applicationId, username, password);
        if (saveSonatypeCredentials) {
            store.save(credentials);
        }
        return credentials;
    }
}
