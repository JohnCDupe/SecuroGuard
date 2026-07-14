package com.securoguard.core.advisory;

import java.util.Optional;

/**
 * A half-open version interval {@code [introduced, fixed)} following the common
 * OSV/GHSA convention: a version is affected if {@code introduced <= v < fixed}.
 * Either bound may be {@code null} (unbounded). This shape is easy to author in a
 * feed and unambiguous to match.
 */
public record VersionRange(String introduced, String fixed) {

    /**
     * True if {@code v} is within {@code [introduced, fixed)}. A malformed version
     * is never in range (safe non-match). A malformed bound is treated as unbounded
     * on that side (conservative — feed bounds are authored and expected valid).
     */
    public boolean contains(Version v) {
        if (v == null) {
            return false;
        }
        if (introduced != null && !introduced.isBlank()) {
            Optional<Version> lo = Version.tryParse(introduced);
            if (lo.isPresent() && v.compareTo(lo.get()) < 0) {
                return false;
            }
        }
        if (fixed != null && !fixed.isBlank()) {
            Optional<Version> hi = Version.tryParse(fixed);
            if (hi.isPresent()) {
                return v.compareTo(hi.get()) < 0;
            }
        }
        return true;
    }

    /** Convenience: parse {@code raw} and test containment; malformed input is a non-match. */
    public boolean containsRaw(String raw) {
        return Version.tryParse(raw).map(this::contains).orElse(false);
    }

    public static VersionRange any() {
        return new VersionRange(null, null);
    }
}
