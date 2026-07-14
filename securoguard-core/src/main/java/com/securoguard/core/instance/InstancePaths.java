package com.securoguard.core.instance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

/**
 * Canonical set of directories that describe a single Minecraft instance from
 * SecuroGuard's point of view.
 *
 * <p>SecuroGuard never assumes the game lives in the platform default
 * {@code .minecraft} directory. Every path is derived from an explicit game
 * directory supplied by the caller (Fabric Loader, the Sentinel {@code --game-dir}
 * flag, or a future launcher adapter).
 *
 * <p>All stored paths are {@linkplain Path#toAbsolutePath() absolute} and
 * {@linkplain Path#normalize() normalized}. We deliberately do <em>not</em> call
 * {@link Path#toRealPath} here: resolving symlinks/junctions is a security-relevant
 * decision handled by {@link PathSecurity}, not something we want to do silently.
 */
public final class InstancePaths {

    private final Path gameDir;
    private final Path modsDir;
    private final Path configDir;
    private final Path dataDir;
    private final Path quarantineDir;

    private InstancePaths(Path gameDir, Path modsDir, Path configDir, Path dataDir, Path quarantineDir) {
        this.gameDir = gameDir;
        this.modsDir = modsDir;
        this.configDir = configDir;
        this.dataDir = dataDir;
        this.quarantineDir = quarantineDir;
    }

    /**
     * Derives the standard instance layout from a game directory.
     *
     * <ul>
     *   <li>{@code <game>/mods}    — where mod JARs live</li>
     *   <li>{@code <game>/config}  — mod configuration</li>
     *   <li>{@code <game>/securoguard}       — SecuroGuard data (baseline, logs)</li>
     *   <li>{@code <game>/securoguard/quarantine} — quarantined files</li>
     * </ul>
     */
    public static InstancePaths ofGameDir(Path gameDir) {
        Objects.requireNonNull(gameDir, "gameDir");
        Path game = gameDir.toAbsolutePath().normalize();
        Path data = game.resolve("securoguard");
        return new InstancePaths(
                game,
                game.resolve("mods"),
                game.resolve("config"),
                data,
                data.resolve("quarantine"));
    }

    /**
     * Ensures the SecuroGuard-owned directories exist. The mods/config directories
     * belong to Minecraft and are intentionally not created here.
     */
    public void createDataDirectories() throws IOException {
        Files.createDirectories(dataDir);
        Files.createDirectories(quarantineDir);
    }

    public Path gameDir() {
        return gameDir;
    }

    public Path modsDir() {
        return modsDir;
    }

    public Path configDir() {
        return configDir;
    }

    public Path dataDir() {
        return dataDir;
    }

    public Path quarantineDir() {
        return quarantineDir;
    }

    /** Path of the persisted baseline file for a given scan scope. */
    public Path baselineFile(ScanScope scope) {
        return dataDir.resolve("baseline-" + scope.id() + ".json");
    }

    /**
     * Resolves a configured instance-relative directory safely, or returns
     * {@code null} if it escapes the instance or is otherwise unsafe. Used to
     * validate user-configured additional monitored directories.
     */
    public Path resolveMonitoredDir(String relative) {
        try {
            return PathSecurity.resolveContainedRelative(gameDir, relative);
        } catch (SecurityException e) {
            return null;
        }
    }

    /**
     * Computes the set of directories a runtime watcher should observe: the mods
     * directory (mandatory) plus every valid configured monitored directory. The
     * result is de-duplicated and order-preserving. Entries that escape the instance
     * are rejected, and SecuroGuard's own data directory (baseline, quarantine, logs)
     * is never watched. Watching is <b>non-recursive</b> (subdirectories are not
     * watched unless configured explicitly).
     */
    public java.util.LinkedHashSet<Path> resolveWatchDirs(java.util.List<String> monitoredRelDirs) {
        java.util.LinkedHashSet<Path> dirs = new java.util.LinkedHashSet<>();
        dirs.add(modsDir); // mandatory, already absolute + normalized
        if (monitoredRelDirs != null) {
            for (String rel : monitoredRelDirs) {
                Path d = resolveMonitoredDir(rel);
                if (d == null) {
                    continue; // escapes the instance or is otherwise unsafe
                }
                if (d.startsWith(dataDir)) {
                    continue; // never watch our own data/quarantine/log directories
                }
                dirs.add(d);
            }
        }
        return dirs;
    }

    /** Directory holding rotating log files. */
    public Path logDir() {
        return dataDir.resolve("logs");
    }

    /**
     * Computes the instance-relative path for a file, or {@code null} if the file
     * lies outside the game directory. Used for reporting and for detecting paths
     * that escape the instance.
     */
    public Path relativize(Path absolute) {
        Path abs = absolute.toAbsolutePath().normalize();
        if (!abs.startsWith(gameDir)) {
            return null;
        }
        return gameDir.relativize(abs);
    }

    @Override
    public String toString() {
        return "InstancePaths{game=" + gameDir + '}';
    }
}
