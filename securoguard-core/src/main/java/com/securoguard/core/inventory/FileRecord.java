package com.securoguard.core.inventory;

import java.util.Objects;

/**
 * Immutable snapshot of a single file within an instance.
 *
 * <p>Paths are stored as strings (the absolute normalized path and the
 * instance-relative path) so records serialize cleanly and remain comparable
 * across runs and platforms. {@code loadedAsMod} is only meaningful when an
 * adapter (the Fabric mod) supplies loader knowledge; the Sentinel, which runs
 * before the game, leaves it {@code false}.
 */
public record FileRecord(
        String absolutePath,
        String relativePath,
        String fileName,
        long size,
        long lastModifiedMillis,
        String sha256,
        FileType detectedType,
        boolean inModsDir,
        boolean loadedAsMod) {

    public FileRecord {
        Objects.requireNonNull(absolutePath, "absolutePath");
        Objects.requireNonNull(relativePath, "relativePath");
        Objects.requireNonNull(fileName, "fileName");
        Objects.requireNonNull(sha256, "sha256");
        Objects.requireNonNull(detectedType, "detectedType");
    }

    /** Returns a copy with the loader-supplied "loaded as a mod" flag set. */
    public FileRecord withLoadedAsMod(boolean loaded) {
        return new FileRecord(absolutePath, relativePath, fileName, size,
                lastModifiedMillis, sha256, detectedType, inModsDir, loaded);
    }

    /**
     * Content-identity check: same bytes (hash) and size. Two files with the same
     * content but different paths/timestamps are considered content-equal, which
     * lets the diff engine recognise renames and replacements.
     */
    public boolean sameContent(FileRecord other) {
        return size == other.size && sha256.equals(other.sha256);
    }
}
