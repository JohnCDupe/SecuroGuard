package com.securoguard.core.advisory;

import java.util.List;

/**
 * A single security advisory. Mirrors the documented feed format (see
 * {@code docs/advisory-format.md}). Matching is intentionally separate from this
 * data class — see {@link AdvisoryMatcher}.
 *
 * @param id                 stable advisory id
 * @param modIds             affected mod ids; empty means "any mod" (e.g. hash-only)
 * @param loader             loader name (e.g. "fabric"); null/blank means any
 * @param minecraftRange     affected Minecraft version range (null means any)
 * @param affectedRanges     affected mod-version ranges (OR-combined)
 * @param fixedVersions      versions that resolve the issue (informational)
 * @param severity           severity label (e.g. "HIGH")
 * @param references         URLs / references
 * @param knownHashes        SHA-256 hashes known to be affected (hash-only match)
 * @param publishedAtMillis  first-published time
 * @param updatedAtMillis    last-updated time
 */
public record Advisory(
        String id,
        List<String> modIds,
        String loader,
        VersionRange minecraftRange,
        List<VersionRange> affectedRanges,
        List<String> fixedVersions,
        String severity,
        List<String> references,
        List<String> knownHashes,
        long publishedAtMillis,
        long updatedAtMillis) {
}
