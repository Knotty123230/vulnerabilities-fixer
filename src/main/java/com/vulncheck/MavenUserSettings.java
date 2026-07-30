package com.vulncheck;

import org.apache.maven.settings.Mirror;
import org.apache.maven.settings.Profile;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Repository;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.Settings;
import org.apache.maven.settings.building.DefaultSettingsBuilderFactory;
import org.apache.maven.settings.building.DefaultSettingsBuildingRequest;
import org.apache.maven.settings.building.SettingsBuildingException;
import org.apache.maven.settings.building.SettingsBuildingResult;
import org.apache.maven.settings.building.SettingsProblem;
import org.eclipse.aether.repository.Authentication;
import org.eclipse.aether.repository.AuthenticationSelector;
import org.eclipse.aether.repository.MirrorSelector;
import org.eclipse.aether.repository.ProxySelector;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.repository.RepositoryPolicy;
import org.eclipse.aether.util.repository.AuthenticationBuilder;
import org.eclipse.aether.util.repository.DefaultAuthenticationSelector;
import org.eclipse.aether.util.repository.DefaultMirrorSelector;
import org.eclipse.aether.util.repository.DefaultProxySelector;
import org.sonatype.plexus.components.cipher.DefaultPlexusCipher;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The user's Maven configuration — {@code ~/.m2/settings.xml} plus the global settings next to the
 * {@code mvn} installation — translated into the selectors Maven Resolver understands.
 *
 * <p>Without this, the tool resolves straight to Maven Central and ignores every mirror, proxy and
 * server credential the developer already has configured. That works on an unrestricted laptop and
 * fails on any machine behind a corporate mirror: {@code mvn} builds the project fine while the
 * tool hangs or 403s on {@code repo.maven.apache.org}, which reads as a mysterious tool bug rather
 * than a configuration gap. The rule here is simple — if {@code mvn} can resolve it, so should we.
 */
public final class MavenUserSettings {

    /** Maven decrypts the master password in settings-security.xml with this fixed key. */
    private static final String SECURITY_KEY = "settings.security";
    private static final Pattern MASTER_ELEMENT = Pattern.compile("<master>(.*?)</master>", Pattern.DOTALL);

    private final Settings settings;

    private MavenUserSettings(Settings settings) {
        this.settings = settings;
    }

    /** Loads the effective settings; never throws — a broken settings.xml degrades to defaults. */
    public static MavenUserSettings load() {
        DefaultSettingsBuildingRequest request = new DefaultSettingsBuildingRequest();
        request.setUserSettingsFile(userSettingsFile());
        request.setGlobalSettingsFile(globalSettingsFile());
        request.setSystemProperties(System.getProperties());

        try {
            SettingsBuildingResult result = new DefaultSettingsBuilderFactory().newInstance().build(request);
            for (SettingsProblem problem : result.getProblems()) {
                Log.debug("settings.xml problem [%s] %s", problem.getSeverity(), problem.getMessage());
            }
            return new MavenUserSettings(result.getEffectiveSettings());
        } catch (SettingsBuildingException e) {
            Log.warn("Could not read Maven settings (%s); falling back to defaults.", Log.describe(e));
            return new MavenUserSettings(new Settings());
        }
    }

    private static File userSettingsFile() {
        return Path.of(System.getProperty("user.home"), ".m2", "settings.xml").toFile();
    }

    /**
     * Locates the installation-wide settings. {@code maven.home} is only set when running inside
     * Maven, so the {@code MAVEN_HOME} / {@code M2_HOME} environment is consulted too.
     */
    private static File globalSettingsFile() {
        for (String home : new String[]{
                System.getProperty("maven.home"), System.getenv("MAVEN_HOME"), System.getenv("M2_HOME")}) {
            if (home != null && !home.isBlank()) {
                File candidate = Path.of(home, "conf", "settings.xml").toFile();
                if (candidate.isFile()) {
                    return candidate;
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Values
    // ------------------------------------------------------------------

    /** The configured local repository, or the {@code ~/.m2/repository} default. */
    public Path localRepository() {
        String configured = settings.getLocalRepository();
        if (configured != null && !configured.isBlank()) {
            return Path.of(configured.trim());
        }
        return Path.of(System.getProperty("user.home"), ".m2", "repository");
    }

    public boolean isOffline() {
        return settings.isOffline();
    }

    public boolean hasMirrors() {
        return !settings.getMirrors().isEmpty();
    }

    public boolean hasProxies() {
        return settings.getProxies().stream().anyMatch(Proxy::isActive);
    }

    /** Short description for the run header, so users can see what was picked up. */
    public String describe() {
        List<String> parts = new ArrayList<>();
        if (hasMirrors()) {
            parts.add(settings.getMirrors().size() + " mirror(s)");
        }
        if (hasProxies()) {
            parts.add("proxy");
        }
        if (!settings.getServers().isEmpty()) {
            parts.add(settings.getServers().size() + " server credential(s)");
        }
        return parts.isEmpty() ? "no mirrors or proxies configured" : String.join(", ", parts);
    }

    // ------------------------------------------------------------------
    // Selectors
    // ------------------------------------------------------------------

    public MirrorSelector mirrorSelector() {
        DefaultMirrorSelector selector = new DefaultMirrorSelector();
        for (Mirror mirror : settings.getMirrors()) {
            selector.add(
                    mirror.getId(),
                    mirror.getUrl(),
                    mirror.getLayout(),
                    false,
                    mirror.isBlocked(),
                    mirror.getMirrorOf(),
                    mirror.getMirrorOfLayouts());
            Log.debug("Mirror %s (%s) -> %s", mirror.getId(), mirror.getMirrorOf(), mirror.getUrl());
        }
        return selector;
    }

    public ProxySelector proxySelector() {
        DefaultProxySelector selector = new DefaultProxySelector();
        for (Proxy proxy : settings.getProxies()) {
            if (!proxy.isActive()) {
                continue;
            }
            AuthenticationBuilder auth = new AuthenticationBuilder();
            if (proxy.getUsername() != null) {
                auth.addUsername(proxy.getUsername()).addPassword(decrypt(proxy.getPassword()));
            }
            selector.add(
                    new org.eclipse.aether.repository.Proxy(
                            proxy.getProtocol(), proxy.getHost(), proxy.getPort(), auth.build()),
                    proxy.getNonProxyHosts());
            Log.debug("Proxy %s://%s:%d", proxy.getProtocol(), proxy.getHost(), proxy.getPort());
        }
        return selector;
    }

    public AuthenticationSelector authenticationSelector() {
        DefaultAuthenticationSelector selector = new DefaultAuthenticationSelector();
        for (Server server : settings.getServers()) {
            AuthenticationBuilder auth = new AuthenticationBuilder();
            if (server.getUsername() != null) {
                auth.addUsername(server.getUsername()).addPassword(decrypt(server.getPassword()));
            }
            if (server.getPrivateKey() != null) {
                auth.addPrivateKey(server.getPrivateKey(), decrypt(server.getPassphrase()));
            }
            Authentication authentication = auth.build();
            if (authentication != null) {
                selector.add(server.getId(), authentication);
                Log.debug("Credentials configured for server '%s'", server.getId());
            }
        }
        return selector;
    }

    /**
     * Repositories declared by active profiles. Many organisations point developers at an internal
     * repository this way rather than through a mirror, so ignoring profiles would leave those
     * machines resolving against Central alone.
     */
    public List<RemoteRepository> activeProfileRepositories() {
        Set<String> active = new HashSet<>(settings.getActiveProfiles());
        List<RemoteRepository> repositories = new ArrayList<>();

        for (Profile profile : settings.getProfiles()) {
            boolean activeByDefault = profile.getActivation() != null && profile.getActivation().isActiveByDefault();
            if (!active.contains(profile.getId()) && !activeByDefault) {
                continue;
            }
            for (Repository repository : profile.getRepositories()) {
                repositories.add(new RemoteRepository.Builder(
                        repository.getId(), repository.getLayout(), repository.getUrl())
                        .setReleasePolicy(toPolicy(repository.getReleases(), true))
                        .setSnapshotPolicy(toPolicy(repository.getSnapshots(), false))
                        .build());
                Log.debug("Profile '%s' repository %s -> %s",
                        profile.getId(), repository.getId(), repository.getUrl());
            }
        }
        return repositories;
    }

    private static RepositoryPolicy toPolicy(org.apache.maven.settings.RepositoryPolicy policy, boolean defaultEnabled) {
        if (policy == null) {
            return new RepositoryPolicy(defaultEnabled,
                    RepositoryPolicy.UPDATE_POLICY_DAILY, RepositoryPolicy.CHECKSUM_POLICY_WARN);
        }
        return new RepositoryPolicy(
                policy.isEnabled(),
                policy.getUpdatePolicy() == null ? RepositoryPolicy.UPDATE_POLICY_DAILY : policy.getUpdatePolicy(),
                policy.getChecksumPolicy() == null
                        ? RepositoryPolicy.CHECKSUM_POLICY_WARN : policy.getChecksumPolicy());
    }

    // ------------------------------------------------------------------
    // Password decryption
    // ------------------------------------------------------------------

    /**
     * Decrypts a {@code {...}} password produced by {@code mvn --encrypt-password}.
     *
     * <p>On any failure the original value is returned unchanged and a warning is logged: a wrong
     * password produces an obvious 401, whereas silently dropping the credential produces a
     * confusing "artifact not found".
     */
    private String decrypt(String value) {
        if (value == null || !value.startsWith("{") || !value.endsWith("}")) {
            return value;
        }
        try {
            Path securityFile = Path.of(System.getProperty(
                    SECURITY_KEY,
                    Path.of(System.getProperty("user.home"), ".m2", "settings-security.xml").toString()));
            if (!Files.isRegularFile(securityFile)) {
                Log.warn("settings.xml contains an encrypted password but %s is missing.", securityFile);
                return value;
            }

            Matcher matcher = MASTER_ELEMENT.matcher(Files.readString(securityFile, StandardCharsets.UTF_8));
            if (!matcher.find()) {
                Log.warn("No <master> element in %s; cannot decrypt settings passwords.", securityFile);
                return value;
            }

            DefaultPlexusCipher cipher = new DefaultPlexusCipher();
            String master = cipher.decryptDecorated(matcher.group(1).trim(), SECURITY_KEY);
            return cipher.decryptDecorated(value, master);
        } catch (Exception e) {
            Log.warn("Could not decrypt a password from settings.xml: %s", Log.describe(e));
            return value;
        }
    }
}
