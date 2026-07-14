package com.securoguard.core.advisory;

/**
 * The explicit outcome of loading an {@link AdvisorySource}. This lets the scanning
 * layer distinguish a <em>legitimately empty</em> feed from a <em>verification or
 * parse failure</em>, so a failed feed becomes a visible degraded-protection finding
 * rather than silently turning into "no advisories, everything looks fine".
 */
public record AdvisoryLoad(Status status, AdvisoryFeed feed, String detail) {

    public enum Status {
        /** Feed obtained and trusted; may contain advisories. */
        LOADED,
        /** Feed obtained and trusted, but contains no advisories. */
        EMPTY,
        /** Ed25519 signature did not verify against the pinned key. */
        SIGNATURE_INVALID,
        /** No pinned public key was available to verify against. */
        KEY_MISSING,
        /** Verified bytes could not be parsed as a feed. */
        PARSE_ERROR,
        /** Feed schema version is not supported. */
        UNSUPPORTED_VERSION
    }

    /** Loaded/empty means the feed can be applied (empty applies zero advisories). */
    public boolean isUsable() {
        return status == Status.LOADED || status == Status.EMPTY;
    }

    /** A failure means advisory protection is degraded and must be surfaced. */
    public boolean isFailure() {
        return !isUsable();
    }

    public static AdvisoryLoad loaded(AdvisoryFeed feed) {
        return new AdvisoryLoad(
                feed.advisories().isEmpty() ? Status.EMPTY : Status.LOADED, feed, null);
    }

    public static AdvisoryLoad failure(Status status, String detail) {
        return new AdvisoryLoad(status, AdvisoryFeed.empty(), detail);
    }
}
