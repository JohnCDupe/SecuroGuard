package com.securoguard.core.inventory;

import java.util.List;

/**
 * The categorised difference between two inventories (typically the trusted
 * baseline vs. a fresh scan).
 *
 * <ul>
 *   <li>{@code added}    — a path present now but not in the baseline.</li>
 *   <li>{@code removed}  — a path present in the baseline but gone now.</li>
 *   <li>{@code modified} — same path, content changed in place (same file type).</li>
 *   <li>{@code replaced} — same path, but the file type changed, i.e. a different
 *       kind of file now occupies that name.</li>
 *   <li>{@code renamed}  — a removed path and an added path with identical content;
 *       inferred, not observed.</li>
 * </ul>
 */
public record DiffResult(
        List<FileRecord> added,
        List<FileRecord> removed,
        List<Change> modified,
        List<Change> replaced,
        List<Rename> renamed) {

    /** A before/after pair for the same relative path. */
    public record Change(FileRecord before, FileRecord after) {
    }

    /** An inferred rename: same content, different path. */
    public record Rename(FileRecord from, FileRecord to) {
    }

    public boolean isEmpty() {
        return added.isEmpty() && removed.isEmpty() && modified.isEmpty()
                && replaced.isEmpty() && renamed.isEmpty();
    }

    public int totalChanges() {
        return added.size() + removed.size() + modified.size() + replaced.size() + renamed.size();
    }
}
