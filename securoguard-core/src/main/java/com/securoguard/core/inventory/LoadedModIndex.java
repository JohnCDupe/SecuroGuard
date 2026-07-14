package com.securoguard.core.inventory;

import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Associates loader-reported {@link InstalledMod}s with on-disk files by absolute
 * origin path. This is how a filesystem {@link FileRecord} learns it was actually
 * loaded as a mod, and which mod coordinates it carries (for advisory matching).
 *
 * <p>Robustness: a mod may have multiple origins, be nested, or be synthetic with
 * no ordinary file. Origins that cannot be turned into an ordinary path (e.g. a
 * non-default filesystem inside a jar-in-jar) are skipped, never fatal.
 */
public final class LoadedModIndex {

    private final Map<String, InstalledMod> byAbsolutePath = new HashMap<>();

    public LoadedModIndex(List<InstalledMod> mods) {
        if (mods == null) {
            return;
        }
        for (InstalledMod mod : mods) {
            if (mod.synthetic()) {
                continue; // no ordinary file to associate
            }
            for (String origin : mod.originPaths()) {
                String key = normalize(origin);
                if (key != null) {
                    // First writer wins; nested duplicates do not clobber the primary.
                    byAbsolutePath.putIfAbsent(key, mod);
                }
            }
        }
    }

    /** Returns the mod whose origin is exactly this absolute path, if any. */
    public Optional<InstalledMod> forAbsolutePath(String absolutePath) {
        String key = normalize(absolutePath);
        return key == null ? Optional.empty() : Optional.ofNullable(byAbsolutePath.get(key));
    }

    public boolean isEmpty() {
        return byAbsolutePath.isEmpty();
    }

    private static String normalize(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        try {
            return Path.of(path).toAbsolutePath().normalize().toString();
        } catch (InvalidPathException | java.nio.file.FileSystemNotFoundException e) {
            // Origin is not an ordinary path on the default filesystem — skip it.
            return null;
        }
    }
}
