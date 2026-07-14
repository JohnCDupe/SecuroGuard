package com.securoguard.core.inventory;

/**
 * Bounds on a directory scan, so a pathological instance (millions of files, or a
 * single enormous file) cannot make a scan run unbounded. Oversized or excess files
 * are <em>reported as skipped</em>, never silently ignored.
 *
 * @param maxFiles         stop after inventorying this many files (0 = unlimited)
 * @param maxFileSizeBytes files larger than this are recorded as skipped, not hashed
 */
public record ScanLimits(int maxFiles, long maxFileSizeBytes) {

    public static ScanLimits defaults() {
        // 200k files and 512 MB per file comfortably cover real instances while still
        // bounding a hostile one.
        return new ScanLimits(200_000, 512L * 1024 * 1024);
    }

    public boolean fileCountUnlimited() {
        return maxFiles <= 0;
    }
}
