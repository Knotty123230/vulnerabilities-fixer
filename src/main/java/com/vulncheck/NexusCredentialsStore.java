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

/** Stores non-secret Nexus settings in ~/.vulnchecker and the password in macOS Keychain. */
public final class NexusCredentialsStore {
    private static final String CONFIG_FILE_NAME = "nexus.properties";
    private static final String KEYCHAIN_SERVICE = "com.vulncheck.vulnchecker.nexus";
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

    public NexusCredentialsStore() {
        this(Path.of(System.getProperty("user.home"), ".vulnchecker"));
    }

    NexusCredentialsStore(Path configDirectory) {
        this.configDirectory = configDirectory;
        this.configFile = configDirectory.resolve(CONFIG_FILE_NAME);
    }

    public Optional<NexusSettings> loadSettings() {
        if (!Files.isRegularFile(configFile)) {
            return Optional.empty();
        }

        Properties properties = new Properties();
        try (var input = Files.newInputStream(configFile)) {
            properties.load(input);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot read Nexus settings from " + configFile, exception);
        }
        return Optional.of(new NexusSettings(properties.getProperty("url"), properties.getProperty("username")));
    }

    /**
     * Reads the saved password, if there is one.
     *
     * <p>Absence is not an error: on a CI runner there is no Keychain, and the password is
     * expected to arrive through {@code VULNCHECKER_NEXUS_PASSWORD} instead. Throwing here
     * would make the tool unusable in exactly the environment it is built for.
     */
    public Optional<String> loadPassword(String username) {
        if (!isMacOs()) {
            Log.debug("Keychain lookup skipped (not macOS); expecting the password from the environment.");
            return Optional.empty();
        }
        ProcessResult result = runKeychainCommand(
                "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", username, "-w"
        );
        return result.exitCode() == 0 ? Optional.of(result.output().strip()) : Optional.empty();
    }

    public void save(NexusCredentials credentials) {
        createConfigDirectory();
        saveSettings(credentials);

        if (credentials.username() == null || credentials.password() == null) {
            // Anonymous repository: URL alone is worth persisting, there is no secret to store.
            return;
        }
        ProcessResult result = runKeychainCommand(
                "add-generic-password", "-s", KEYCHAIN_SERVICE, "-a", credentials.username(),
                "-w", credentials.password(), "-U"
        );
        if (result.exitCode() != 0) {
            throw new IllegalStateException("Cannot save Nexus password to macOS Keychain.");
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

    private void saveSettings(NexusCredentials credentials) {
        Properties properties = new Properties();
        properties.setProperty("url", credentials.url());
        if (credentials.username() != null) {
            properties.setProperty("username", credentials.username());
        }

        try {
            Path temporaryFile = Files.createTempFile(configDirectory, "nexus", ".properties");
            applyPermissions(temporaryFile, OWNER_ONLY_FILE);
            try (var output = Files.newOutputStream(temporaryFile)) {
                properties.store(output, "Vulnchecker Nexus settings. Password is stored in macOS Keychain.");
            }
            moveAtomically(temporaryFile, configFile);
            applyPermissions(configFile, OWNER_ONLY_FILE);
        } catch (IOException exception) {
            throw new IllegalStateException("Cannot save Nexus settings to " + configFile, exception);
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

    private static boolean isMacOs() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("mac");
    }

    private static ProcessResult runKeychainCommand(String... arguments) {
        if (!isMacOs()) {
            throw new IllegalStateException(
                    "Persistent Nexus passwords require macOS Keychain. Use VULNCHECKER_NEXUS_PASSWORD instead."
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

    public record NexusSettings(String url, String username) {
    }

    private record ProcessResult(int exitCode, String output) {
    }
}
