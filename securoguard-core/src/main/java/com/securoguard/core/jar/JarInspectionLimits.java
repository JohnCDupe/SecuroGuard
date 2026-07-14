package com.securoguard.core.jar;

/**
 * Defensive bounds applied while inspecting an archive. Inspecting a hostile
 * archive must never let it exhaust memory, CPU or time — these limits turn a
 * "zip bomb" or pathological archive into a bounded {@code finding} instead of a
 * crash or hang.
 *
 * @param maxArchiveBytes        archives larger than this are not fully inspected
 * @param maxEntryCount          stop after this many entries
 * @param maxUncompressedBytes   stop after decompressing this many bytes in total
 * @param maxCompressionRatio    flag/stop if uncompressed/compressed exceeds this
 * @param maxNestedDepth         how deep to recurse into nested JARs
 * @param maxMetadataBytes       cap on a single metadata entry we read into memory
 * @param maxInspectionMillis    wall-clock budget for one archive
 * @param maxTotalArchiveBytes   cumulative in-memory budget for all nested archives
 *                               loaded during one inspection (bounds peak memory)
 */
public record JarInspectionLimits(
        long maxArchiveBytes,
        int maxEntryCount,
        long maxUncompressedBytes,
        int maxCompressionRatio,
        int maxNestedDepth,
        int maxMetadataBytes,
        long maxInspectionMillis,
        long maxTotalArchiveBytes) {

    /** Reasonable defaults for real-world mod JARs (which are typically < 50 MB). */
    public static JarInspectionLimits defaults() {
        return new JarInspectionLimits(
                256L * 1024 * 1024,   // 256 MB archive cap
                50_000,               // entry count
                1024L * 1024 * 1024,  // 1 GB total uncompressed
                200,                  // compression ratio
                3,                    // nested-jar depth
                4 * 1024 * 1024,      // 4 MB per metadata entry
                15_000,               // 15 s budget
                128L * 1024 * 1024);  // 128 MB cumulative nested-archive memory
    }
}
