package com.securoguard.core.inventory;

import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.instance.PathSecurity;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.util.Hashing;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

/**
 * Walks an instance directory and builds a {@link FileInventory}, honouring a
 * {@link ScanScope} so the runtime hot path only touches security-relevant files
 * (mods + configured directories) rather than rehashing worlds, logs and caches.
 *
 * <p>The scanner reads file bytes only to hash them (in a single pass that also
 * captures the header for type detection); it never opens archives as archives
 * here and never executes anything. Symbolic links are not followed during the
 * walk so a link cannot redirect the scan outside the instance.
 */
public final class InventoryScanner {

    private final InstancePaths paths;

    public InventoryScanner(InstancePaths paths) {
        this.paths = paths;
    }

    /** Full-instance scan (back-compat convenience; equivalent to scope {@link ScanScope#FULL}). */
    public FileInventory scanInstance() throws IOException {
        return scanScoped(ScanScope.FULL, List.of(), ScanLimits.defaults()).inventory();
    }

    /** Scans only the mods directory. */
    public FileInventory scanModsOnly() throws IOException {
        return scanScoped(ScanScope.RUNTIME, List.of(), ScanLimits.defaults()).inventory();
    }

    /**
     * Scoped scan.
     *
     * @param scope         which parts of the instance to scan
     * @param monitoredDirs additional absolute directories (already validated as
     *                      instance-contained) to include for RUNTIME/PRELAUNCH
     * @param limits        file-count and per-file-size bounds
     */
    public ScopedScan scanScoped(ScanScope scope, List<Path> monitoredDirs, ScanLimits limits) throws IOException {
        Map<String, FileRecord> byRel = new LinkedHashMap<>();
        List<ScopedScan.Skipped> skipped = new ArrayList<>();
        boolean[] truncated = {false};
        for (Path root : rootsFor(scope, monitoredDirs)) {
            if (truncated[0]) {
                break;
            }
            collect(root, byRel, skipped, limits, truncated);
        }
        return new ScopedScan(FileInventory.of(new ArrayList<>(byRel.values())), skipped, truncated[0]);
    }

    private List<Path> rootsFor(ScanScope scope, List<Path> monitoredDirs) {
        List<Path> roots = new ArrayList<>();
        switch (scope) {
            case FULL -> roots.add(paths.gameDir());
            case PRELAUNCH -> {
                roots.add(paths.modsDir());
                roots.add(paths.configDir());
                roots.addAll(monitoredDirs);
            }
            case RUNTIME -> {
                roots.add(paths.modsDir());
                roots.addAll(monitoredDirs);
            }
        }
        return roots;
    }

    /**
     * Builds a single record for one file, or {@code null} if it is not a real
     * regular file. <b>Refuses to follow symbolic links / reparse redirection</b>
     * (R7): a link inside the instance must never cause SecuroGuard to read (and
     * hash) a target elsewhere. Use {@link #linkSkipReason(Path)} to distinguish a
     * skipped link from a genuinely absent/irregular file.
     */
    public FileRecord recordFor(Path file) throws IOException {
        // NOFOLLOW: classify the link itself, not its target.
        if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            return null;
        }
        Path abs = file.toAbsolutePath().normalize();
        if (PathSecurity.isLinkOrRedirect(file)) {
            return null; // junction / reparse-point redirection — never hash through it
        }
        Path relative = paths.relativize(abs);
        String rel = (relative != null) ? relative.toString().replace('\\', '/') : abs.getFileName().toString();
        BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        // Single pass: hash the file and capture its header for classification.
        Hashing.Digest digest = Hashing.sha256AndHeader(file);
        FileType type = FileType.detectFromHeader(digest.header(), digest.headerLen());
        boolean inMods = abs.startsWith(paths.modsDir());
        return new FileRecord(
                abs.toString(), rel, abs.getFileName().toString(),
                attrs.size(), attrs.lastModifiedTime().toMillis(),
                digest.sha256(), type, inMods, false);
    }

    /**
     * If {@code file} is a symbolic link or a reparse/junction redirection, returns a
     * human-readable reason it will be skipped; otherwise {@code null}. Conservative
     * policy: SecuroGuard refuses to follow <em>any</em> file link (in- or
     * out-of-instance) and reports it, rather than risk reading an external target.
     */
    public static String linkSkipReason(Path file) {
        try {
            if (Files.isSymbolicLink(file)) {
                return "symbolic link not followed (not hashed)";
            }
            if (PathSecurity.isLinkOrRedirect(file)) {
                return "path is redirected by a junction/reparse point (not hashed)";
            }
        } catch (RuntimeException e) {
            return "could not verify link status; skipped for safety";
        }
        return null;
    }

    private void collect(Path root, Map<String, FileRecord> out, List<ScopedScan.Skipped> skipped,
                         ScanLimits limits, boolean[] truncated) throws IOException {
        if (!Files.isDirectory(root)) {
            return;
        }
        Path dataDir = paths.dataDir();
        // Never follow links while walking: a junction in mods/ must not let the walk
        // wander into the wider filesystem. Skip SecuroGuard's own data dir.
        try (Stream<Path> walk = Files.walk(root)) {
            for (var it = walk.iterator(); it.hasNext(); ) {
                Path p = it.next();
                if (truncated[0]) {
                    return;
                }
                Path abs = p.toAbsolutePath().normalize();
                if (abs.startsWith(dataDir)) {
                    continue;
                }
                String rel = relativeOf(abs);
                if (out.containsKey(rel)) {
                    continue; // dedup across overlapping roots
                }
                // R7: never follow a file link to a target (possibly outside the instance).
                String linkReason = linkSkipReason(p);
                if (linkReason != null) {
                    skipped.add(new ScopedScan.Skipped(rel, linkReason));
                    continue;
                }
                if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS)) {
                    continue; // directory or special file
                }
                if (!limits.fileCountUnlimited() && out.size() >= limits.maxFiles()) {
                    truncated[0] = true;
                    skipped.add(new ScopedScan.Skipped(rel, "scan truncated: file-count limit "
                            + limits.maxFiles() + " reached"));
                    return;
                }
                try {
                    long size = Files.size(p);
                    if (size > limits.maxFileSizeBytes()) {
                        skipped.add(new ScopedScan.Skipped(rel,
                                "skipped: file size " + size + " exceeds limit " + limits.maxFileSizeBytes()));
                        continue;
                    }
                    FileRecord r = recordFor(p);
                    if (r != null) {
                        out.put(rel, r);
                    }
                } catch (IOException e) {
                    // Report unreadable files rather than silently dropping them.
                    skipped.add(new ScopedScan.Skipped(rel, "unreadable: " + e.getMessage()));
                }
            }
        } catch (UncheckedIOException e) {
            throw e.getCause();
        }
    }

    private String relativeOf(Path abs) {
        Path relative = paths.relativize(abs);
        return (relative != null) ? relative.toString().replace('\\', '/') : abs.getFileName().toString();
    }
}
