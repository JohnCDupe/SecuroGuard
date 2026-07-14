package com.securoguard.core.advisory;

/**
 * A trusted way to obtain an {@link AdvisoryFeed}. Kept as an abstraction so the
 * scanning layer never cares <em>where</em> a feed came from, only that whatever
 * produced it applied the appropriate trust checks.
 *
 * <p>{@link #load()} returns an explicit {@link AdvisoryLoad} so a verification or
 * parse failure is distinguishable from a legitimately empty feed — unverified
 * content is never applied, and a failure becomes a visible degraded-protection
 * finding rather than silently disappearing.
 *
 * <p>Two trusted implementations exist:
 * <ul>
 *   <li>{@link BundledAdvisorySource} — the feed shipped inside the (release-signed) jar.</li>
 *   <li>{@link VerifiedAdvisorySource} — feed bytes that must pass Ed25519 verification
 *       against a pinned key before being parsed.</li>
 * </ul>
 * There is deliberately <b>no unsigned remote-fetch source</b> in this MVP.
 */
public interface AdvisorySource {

    /** Loads the feed with an explicit status. Must never throw for a routine failure. */
    AdvisoryLoad load();
}
