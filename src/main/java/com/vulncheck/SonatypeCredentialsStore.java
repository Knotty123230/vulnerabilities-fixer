package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;

/** Stores Sonatype settings in ~/.vulnchecker and the password in macOS Keychain. */
public final class SonatypeCredentialsStore {
    private static final String CONFIG_FILE_NAME = "sonatype.properties";
    private static final String KEYCHAIN_SERVICE = "com.vulncheck.vulnchecker.sonatype";
    private static final Set<PosixFilePermission> OWNER_ONLY_DIRECTORY = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE
    );
    private static final Set<PosixFilePermission> OWNER_ONLY_FILE = EnumSet.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE
    );

    private final Path configDirectory;
    private final Path configFile;

    public SonatypeCredentialsStore() {
        this(Path.of(System.getProperty("user.home"), ".vulnchecker"));
    }

    SonatypeCredentialsStore(Path configDirectory) {
        this.configDirectory = configDirectory;
        this.configFile = configDirectory.resolve(CONFIG_FILE_NAME);
    }

    public SonatypeCredentials getCredentials() {
        SonatypeSettings settings = loadSettings().orElseThrow(() -> new IllegalStateException(
                "Sonatype settings are missing. Provide --sonatype-url, --sonatype-application-id, "
                        + "--sonatype-username and --sonatype-password with --save-sonatype-credentials."
        ));
        String password = loadPassword(settings.username()).orElseThrow(() -> new IllegalStateException(
                "Sonatype password is missing from macOS Keychain for " + settings.username()
        ));
        return new SonatypeCredentials(
                settings.serverUrl(),
                settings.applicationId(),
                settings.username(),
                password
        );
    }

    public Optional<SonatypeSettings> loadSettings() {
        if (!Files.isRegularFile(configFile)) {
            return Optional.empty();
        }

        Properties properties = new Properties();
        try (var input = Files.newInputStream(configFile)) {
            properties.load(input);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot read Sonatype settings from " + configFile, exception);
        }
        return Optional.of(new SonatypeSettings(
                properties.getProperty("serverUrl"),
                properties.getProperty("applicationId"),
                properties.getProperty("username")
        ));
    }

    public Optional<String> loadPassword(String username) {
        ProcessResult result = runKeychainCommand(
                "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", username, "-w"
        );
        return result.exitCode() == 0 ? Optional.of(result.output()) : Optional.empty();
    }

    public void save(SonatypeCredentials credentials) {
        createConfigDirectory();
        saveSettings(credentials);

        ProcessResult result = runKeychainCommand(
                "add-generic-password", "-s", KEYCHAIN_SERVICE, "-a", credentials.sonatypeUsername(),
                "-w", credentials.sonatypePassword(), "-U"
        );
        if (result.exitCode() != 0) {
            throw new IllegalStateException("Cannot save Sonatype password to macOS Keychain.");
        }
    }

    private void createConfigDirectory() {
        try {
            Files.createDirectories(configDirectory);
            applyPermissions(configDirectory, OWNER_ONLY_DIRECTORY);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot create configuration directory " + configDirectory, exception);
        }
    }

    private void saveSettings(SonatypeCredentials credentials) {
        Properties properties = new Properties();
        properties.setProperty("serverUrl", credentials.serverUrl());
        properties.setProperty("applicationId", credentials.applicationId());
        properties.setProperty("username", credentials.sonatypeUsername());

        try {
            Path temporaryFile = Files.createTempFile(configDirectory, "sonatype", ".properties");
            applyPermissions(temporaryFile, OWNER_ONLY_FILE);
            try (var output = Files.newOutputStream(temporaryFile)) {
                properties.store(output, "Vulnchecker Sonatype settings. Password is stored in macOS Keychain.");
            }
            moveAtomically(temporaryFile, configFile);
            applyPermissions(configFile, OWNER_ONLY_FILE);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot save Sonatype settings to " + configFile, exception);
        }
    }

    private static void moveAtomically(Path source, Path target) throws IOException {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void applyPermissions(Path path, Set<PosixFilePermission> permissions) throws IOException {
        try {
            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException ignored) {
            // Windows protects the user's profile through ACLs instead.
        }
    }

    private static ProcessResult runKeychainCommand(String... arguments) {
        if (!System.getProperty("os.name").toLowerCase().contains("mac")) {
            throw new IllegalStateException(
                    "Persistent Sonatype passwords require macOS Keychain. Use VULNCHECKER_SONATYPE_PASSWORD instead."
            );
        }

        String[] command = new String[arguments.length + 1];
        command[0] = "security";
        System.arraycopy(arguments, 0, command, 1, arguments.length);

        try {
            Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return new ProcessResult(process.waitFor(), output);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot access macOS Keychain.", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Access to macOS Keychain was interrupted.", exception);
        }
    }

    public record SonatypeSettings(String serverUrl, String applicationId, String username) {
    }

    private record ProcessResult(int exitCode, String output) {
    }
}
