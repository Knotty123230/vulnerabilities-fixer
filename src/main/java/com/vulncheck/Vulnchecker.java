package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.repository.RemoteRepository;
import picocli.CommandLine;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * Command-line entry point.
 *
 * <p>Designed to be run unattended in a pipeline: the exit code carries the verdict, the report
 * can be written to a file in a machine-readable format, and everything printed to stdout is
 * either the report or progress a human would want in a job log.
 */
@CommandLine.Command(
        name = "vulnchecker",
        mixinStandardHelpOptions = true,
        version = "vulnchecker 2.0",
        sortOptions = false,
        usageHelpAutoWidth = true,
        description = "Scans a Maven project for vulnerable dependencies and applies verified "
                + "version fixes to its POM.",
        footer = {
                "",
                "Exit codes:",
                "  0  no outstanding findings at or above the --fail-on threshold",
                "  1  outstanding findings at or above the threshold (CI gate failed)",
                "  2  the tool could not complete the scan",
                "",
                "Examples:",
                "  vulnchecker -p . --scan-sonatype --dry-run",
                "  vulnchecker -p . --scan-sonatype --report-format markdown --report-file report.md",
                "  vulnchecker -p . --scan-sonatype --upgrade-scope patch --fail-on critical"
        })
public class Vulnchecker implements Callable<Integer> {

    private static final int EXIT_OK = 0;
    private static final int EXIT_GATE_FAILED = 1;
    private static final int EXIT_ERROR = 2;

    /** Formats for {@code --report-file}. The console summary is always printed regardless. */
    public enum ReportFormat { MARKDOWN, JSON }

    public enum SeverityThreshold {
        CRITICAL(4), HIGH(3), MEDIUM(2), LOW(1), ANY(1), NONE(Integer.MAX_VALUE);

        private final int rank;

        SeverityThreshold(int rank) {
            this.rank = rank;
        }
    }

    // ---------------- project ----------------

    @CommandLine.Option(
            names = {"-p", "--project", "-f", "--file"},
            paramLabel = "DIR",
            required = true,
            description = "Maven project directory (the one containing pom.xml).")
    private Path projectPath;

    // ---------------- behaviour ----------------

    @CommandLine.Option(
            names = "--dry-run",
            description = "Report what would change without writing to any pom.xml.")
    private boolean dryRun;

    @CommandLine.Option(
            names = "--upgrade-scope",
            paramLabel = "SCOPE",
            defaultValue = "MINOR",
            description = "How far versions may move: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}.")
    private VersionPolicy.UpgradeScope upgradeScope;

    @CommandLine.Option(
            names = "--check-linkage",
            description = "Verify binary compatibility of each fix against the project's compiled "
                    + "classes. Requires a prior `mvn compile`; slower, but catches upgrades that "
                    + "would fail at runtime with NoSuchMethodError.")
    private boolean checkLinkage;

    @CommandLine.Option(
            names = "--max-candidates",
            paramLabel = "N",
            defaultValue = "12",
            description = "Upper bound on versions tried per strategy. Default: ${DEFAULT-VALUE}.")
    private int maxCandidates;

    @CommandLine.Option(
            names = "--fail-on",
            paramLabel = "SEVERITY",
            defaultValue = "HIGH",
            description = "Exit non-zero when an outstanding finding reaches this severity: "
                    + "${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}.")
    private SeverityThreshold failOn;

    // ---------------- reporting ----------------

    @CommandLine.Option(
            names = "--report-format",
            paramLabel = "FORMAT",
            defaultValue = "MARKDOWN",
            description = "Format for --report-file: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}. "
                    + "The console summary is printed either way.")
    private ReportFormat reportFormat;

    @CommandLine.Option(
            names = "--report-file",
            paramLabel = "FILE",
            description = "Write the report here in addition to the console summary.")
    private Path reportFile;

    @CommandLine.Option(names = {"-q", "--quiet"}, description = "Print the report only, no progress.")
    private boolean quiet;

    @CommandLine.Option(names = {"-v", "--verbose"}, description = "Print resolver and recipe diagnostics.")
    private boolean verbose;

    @CommandLine.Option(
            names = "--color",
            paramLabel = "WHEN",
            defaultValue = "AUTO",
            description = "Colourise output: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}.")
    private Log.ColorMode color;

    // ---------------- Nexus ----------------

    @CommandLine.Option(names = "--nexus-url", description = "Nexus repository URL. Omitted: Maven Central.")
    private String nexusUrl;

    @CommandLine.Option(names = "--nexus-username", description = "Nexus username.")
    private String nexusUsername;

    @CommandLine.Option(
            names = "--nexus-password",
            arity = "0..1",
            interactive = true,
            description = "Nexus password. Supplied without a value, prompts without echo. "
                    + "Also read from VULNCHECKER_NEXUS_PASSWORD.")
    private String nexusPassword;

    @CommandLine.Option(
            names = "--save-nexus-credentials",
            description = "Save URL and username in ~/.vulnchecker; store the password in the OS keychain.")
    private boolean saveNexusCredentials;

    // ---------------- Sonatype ----------------

    @CommandLine.Option(names = "--scan-sonatype", description = "Run a Sonatype Lifecycle evaluation first.")
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
            description = "Sonatype Lifecycle password. Supplied without a value, prompts without echo. "
                    + "Also read from VULNCHECKER_SONATYPE_PASSWORD.")
    private String sonatypePassword;

    @CommandLine.Option(
            names = "--save-sonatype-credentials",
            description = "Save Sonatype URL, application ID and username in ~/.vulnchecker; "
                    + "store the password in the OS keychain.")
    private boolean saveSonatypeCredentials;

    public static void main(String[] args) {
        System.exit(new CommandLine(new Vulnchecker()).execute(args));
    }

    @Override
    public Integer call() {
        Log.configure(verbosityLevel(), color);

        try {
            File pomFile = validateProject();
            NexusCredentials credentials = resolveNexusCredentials();

            SonatypeScanReport scanReport = obtainScanReport();
            if (scanReport == null) {
                Log.error("No vulnerability data. Pass --scan-sonatype to run a Sonatype Lifecycle evaluation.");
                return EXIT_ERROR;
            }

            ScanReport report = remediate(pomFile, credentials, scanReport);

            ConsoleReportRenderer.render(report);
            writeReportFile(report);

            return gateVerdict(report);

        } catch (Exception e) {
            Log.error(e, "Scan could not be completed.");
            return EXIT_ERROR;
        }
    }

    private Log.Level verbosityLevel() {
        if (verbose) {
            return Log.Level.VERBOSE;
        }
        return quiet ? Log.Level.QUIET : Log.Level.NORMAL;
    }

    private File validateProject() {
        Path project = projectPath.toAbsolutePath().normalize();
        if (!Files.isDirectory(project)) {
            throw new IllegalArgumentException("Not a directory: " + project);
        }
        File pomFile = project.resolve("pom.xml").toFile();
        if (!pomFile.isFile()) {
            throw new IllegalArgumentException("No pom.xml in " + project);
        }
        projectPath = project;
        Log.info("%s %s", Log.bold("Project"), project);
        return pomFile;
    }

    private SonatypeScanReport obtainScanReport() {
        if (!scanSonatype) {
            return null;
        }
        Log.section("Running Sonatype Lifecycle evaluation");
        SonatypeCredentials credentials = resolveSonatypeCredentials();
        SonatypeScanReport report = new SonatypeProcessor(credentials).scan(projectPath, credentials.applicationId());
        Log.step("%d component(s) scanned, %d vulnerable", report.totalComponents(), report.vulnerableComponents());
        if (report.reportUrl() != null) {
            Log.step("Full report: %s", report.reportUrl());
        }
        return report;
    }

    private ScanReport remediate(File pomFile, NexusCredentials credentials, SonatypeScanReport scanReport)
            throws Exception {
        RepositorySystem repositorySystem = MavenResolverFactory.createRepositorySystem();
        RepositorySystemSession session = MavenResolverFactory.createSession(
                repositorySystem, MavenResolverFactory.defaultLocalRepository(), credentials);
        List<RemoteRepository> repositories = MavenResolverFactory.createRepositories(credentials);

        Log.info("%-12s %s", "Repository", repositories.getFirst().getUrl());
        Log.info("%-12s %s%s", "Policy", upgradeScope.describe(), dryRun ? ", dry run" : "");

        RemediationEngine.Options options = new RemediationEngine.Options(
                upgradeScope, dryRun, checkLinkage, Math.max(1, maxCandidates));

        return new RemediationEngine(
                scanReport, repositorySystem, session, repositories, credentials, projectPath, options)
                .run(pomFile);
    }

    private void writeReportFile(ScanReport report) {
        if (reportFile == null) {
            return;
        }
        try {
            String content = switch (reportFormat) {
                case JSON -> jsonMapper().writeValueAsString(report);
                case MARKDOWN -> MarkdownReportRenderer.render(report);
            };
            Path target = reportFile.toAbsolutePath().normalize();
            if (target.getParent() != null) {
                Files.createDirectories(target.getParent());
            }
            Files.writeString(target, content);
            Log.report("");
            Log.report("Report written to %s", target);
        } catch (Exception e) {
            // A failure to write an auxiliary file must not change the security verdict.
            Log.warn("Could not write report to %s: %s", reportFile, Log.describe(e));
        }
    }

    private static ObjectMapper jsonMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    /** Translates the report into the process exit code a pipeline gates on. */
    private int gateVerdict(ScanReport report) {
        int highest = report.highestOutstandingSeverity();
        if (failOn == SeverityThreshold.NONE || highest < failOn.rank) {
            Log.report(Log.green("Gate passed") + " (threshold: " + failOn + ")");
            return EXIT_OK;
        }
        Log.report(Log.red("Gate failed") + " — outstanding findings at "
                + VersionPolicy.severityLabel(highest) + " (threshold: " + failOn + ")");
        return EXIT_GATE_FAILED;
    }

    // ------------------------------------------------------------------
    // Credentials
    // ------------------------------------------------------------------

    /**
     * Resolves Nexus settings from flags, then the environment, then saved settings.
     * Returns {@code null} when no Nexus is configured — the tool then uses Maven Central,
     * which is the right default for open-source projects.
     */
    private NexusCredentials resolveNexusCredentials() {
        NexusCredentialsStore store = new NexusCredentialsStore();
        Optional<NexusCredentialsStore.NexusSettings> saved = store.loadSettings();

        String url = firstNonBlank(nexusUrl,
                System.getenv("VULNCHECKER_NEXUS_URL"),
                saved.map(NexusCredentialsStore.NexusSettings::url).orElse(null));
        if (url == null) {
            Log.debug("No Nexus configured; using Maven Central.");
            return null;
        }

        String username = firstNonBlank(nexusUsername,
                System.getenv("VULNCHECKER_NEXUS_USERNAME"),
                saved.map(NexusCredentialsStore.NexusSettings::username).orElse(null));
        String password = firstNonBlank(nexusPassword,
                System.getenv("VULNCHECKER_NEXUS_PASSWORD"),
                username == null ? null : store.loadPassword(username).orElse(null));

        NexusCredentials credentials = new NexusCredentials(url, username, password);
        if (saveNexusCredentials) {
            store.save(credentials);
            Log.info("Nexus credentials saved.");
        }
        return credentials;
    }

    private SonatypeCredentials resolveSonatypeCredentials() {
        SonatypeCredentialsStore store = new SonatypeCredentialsStore();
        Optional<SonatypeCredentialsStore.SonatypeSettings> saved = store.loadSettings();

        String url = firstNonBlank(sonatypeUrl,
                System.getenv("VULNCHECKER_SONATYPE_URL"),
                saved.map(SonatypeCredentialsStore.SonatypeSettings::serverUrl).orElse(null));
        String applicationId = firstNonBlank(sonatypeApplicationId,
                System.getenv("VULNCHECKER_SONATYPE_APPLICATION_ID"),
                saved.map(SonatypeCredentialsStore.SonatypeSettings::applicationId).orElse(null));
        String username = firstNonBlank(sonatypeUsername,
                System.getenv("VULNCHECKER_SONATYPE_USERNAME"),
                saved.map(SonatypeCredentialsStore.SonatypeSettings::username).orElse(null));
        String password = firstNonBlank(sonatypePassword,
                System.getenv("VULNCHECKER_SONATYPE_PASSWORD"),
                username == null ? null : store.loadPassword(username).orElse(null));

        requireConfigured(url, "--sonatype-url");
        requireConfigured(applicationId, "--sonatype-application-id");
        requireConfigured(username, "--sonatype-username");
        requireConfigured(password, "--sonatype-password (or VULNCHECKER_SONATYPE_PASSWORD)");

        SonatypeCredentials credentials = new SonatypeCredentials(url, applicationId, username, password);
        if (saveSonatypeCredentials) {
            store.save(credentials);
            Log.info("Sonatype credentials saved.");
        }
        return credentials;
    }

    private static void requireConfigured(String value, String option) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "Sonatype scan requested but " + option + " is not set "
                            + "(pass the flag, set the environment variable, or run once with "
                            + "--save-sonatype-credentials).");
        }
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }
}
