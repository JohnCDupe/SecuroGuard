package com.securoguard.core.inventory;

import java.util.List;

/**
 * The result of a scoped directory scan: the inventory that was built, the files
 * that were deliberately skipped (with a reason), and whether the scan was
 * truncated by a limit.
 *
 * @param inventory the files successfully inventoried
 * @param skipped   files not inventoried (oversized, unreadable) — surfaced, not hidden
 * @param truncated true if a file-count limit stopped the scan early
 */
public record ScopedScan(FileInventory inventory, List<Skipped> skipped, boolean truncated) {

    /** A file that was not inventoried, and why. */
    public record Skipped(String relativePath, String reason) {
    }
}
