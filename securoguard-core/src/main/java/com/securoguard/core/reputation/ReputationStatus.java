package com.securoguard.core.reputation;

/**
 * Outcome of a hash-reputation lookup. Deliberately coarse and, crucially,
 * <em>never</em> asserts "malicious": absence from a hosting platform is not
 * evidence of malice (private packs, dev builds and brand-new mods are all
 * legitimately unknown).
 */
public enum ReputationStatus {
    /** The hash is recognised by a hosting platform (e.g. present on Modrinth). */
    KNOWN_ON_PLATFORM,
    /** The hash is not recognised. Informational only — not suspicious by itself. */
    UNKNOWN,
    /** The lookup could not be completed (offline, timeout, rate-limited). */
    LOOKUP_UNAVAILABLE
}
