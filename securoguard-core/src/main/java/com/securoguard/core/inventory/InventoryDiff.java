package com.securoguard.core.inventory;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Computes a {@link DiffResult} between a baseline inventory and a current one.
 *
 * <p>The algorithm is deliberately simple and deterministic so that findings are
 * reproducible:
 * <ol>
 *   <li>Partition by relative path into added / removed / (present-in-both).</li>
 *   <li>For present-in-both, classify unchanged / modified / replaced.</li>
 *   <li>Infer renames by pairing removed and added records that share a SHA-256.</li>
 * </ol>
 */
public final class InventoryDiff {

    private InventoryDiff() {
    }

    public static DiffResult compute(FileInventory baseline, FileInventory current) {
        List<FileRecord> added = new ArrayList<>();
        List<FileRecord> removed = new ArrayList<>();
        List<DiffResult.Change> modified = new ArrayList<>();
        List<DiffResult.Change> replaced = new ArrayList<>();

        for (FileRecord cur : current.records()) {
            FileRecord base = baseline.get(cur.relativePath());
            if (base == null) {
                added.add(cur);
            } else if (base.sameContent(cur)) {
                // unchanged
            } else if (base.detectedType() != cur.detectedType()) {
                replaced.add(new DiffResult.Change(base, cur));
            } else {
                modified.add(new DiffResult.Change(base, cur));
            }
        }

        for (FileRecord base : baseline.records()) {
            if (!current.contains(base.relativePath())) {
                removed.add(base);
            }
        }

        List<DiffResult.Rename> renamed = inferRenames(removed, added);
        return new DiffResult(added, removed, modified, replaced, renamed);
    }

    /**
     * Pairs removed and added records with identical content hashes as renames,
     * removing the paired entries from the added/removed lists in place. Greedy:
     * if several files share content, they are paired in encounter order.
     */
    private static List<DiffResult.Rename> inferRenames(List<FileRecord> removed, List<FileRecord> added) {
        List<DiffResult.Rename> renames = new ArrayList<>();
        if (removed.isEmpty() || added.isEmpty()) {
            return renames;
        }
        // Queue of removed records per content hash, so pairing consumes each once.
        Map<String, Deque<FileRecord>> removedByHash = new HashMap<>();
        for (FileRecord r : removed) {
            removedByHash.computeIfAbsent(r.sha256(), k -> new ArrayDeque<>()).add(r);
        }

        List<FileRecord> remainingAdded = new ArrayList<>();
        List<FileRecord> pairedRemoved = new ArrayList<>();
        for (FileRecord a : added) {
            Deque<FileRecord> candidates = removedByHash.get(a.sha256());
            if (candidates != null && !candidates.isEmpty()) {
                FileRecord from = candidates.poll();
                pairedRemoved.add(from);
                renames.add(new DiffResult.Rename(from, a));
            } else {
                remainingAdded.add(a);
            }
        }

        // Rebuild the input lists to exclude the paired entries (identity-based).
        added.clear();
        added.addAll(remainingAdded);
        removed.removeAll(pairedRemoved);
        return renames;
    }
}
