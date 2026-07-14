package com.securoguard.core.advisory;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

/**
 * Wraps raw feed bytes + a detached Ed25519 signature and only ever yields the
 * parsed feed if the signature verifies against the pinned public key. This is the
 * enforcement point promised in the threat model: <b>remote/untrusted advisory bytes
 * can never be applied without a valid signature.</b>
 *
 * <p>Fail-closed and <em>explicit</em>: a missing key, an invalid signature, a parse
 * failure or an unsupported schema each yield a distinct {@link AdvisoryLoad.Status}
 * so the scanning layer surfaces degraded protection rather than silently applying an
 * empty feed. This class performs no network I/O — obtaining the bytes is the
 * caller's concern; trust is established here. Untrusted feed bytes are never logged.
 */
public final class VerifiedAdvisorySource implements AdvisorySource {

    private final byte[] feedBytes;
    private final byte[] signature;
    private final PublicKey pinnedKey;

    public VerifiedAdvisorySource(byte[] feedBytes, byte[] signature, PublicKey pinnedKey) {
        this.feedBytes = feedBytes == null ? new byte[0] : feedBytes.clone();
        this.signature = signature == null ? new byte[0] : signature.clone();
        this.pinnedKey = pinnedKey;
    }

    @Override
    public AdvisoryLoad load() {
        if (pinnedKey == null) {
            return AdvisoryLoad.failure(AdvisoryLoad.Status.KEY_MISSING,
                    "no pinned public key available to verify the advisory feed");
        }
        if (!AdvisoryFeedVerifier.verify(feedBytes, signature, pinnedKey)) {
            return AdvisoryLoad.failure(AdvisoryLoad.Status.SIGNATURE_INVALID,
                    "advisory feed signature did not verify against the pinned key");
        }
        AdvisoryFeed feed;
        try {
            feed = AdvisoryFeed.fromJson(new String(feedBytes, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            // Do NOT echo the untrusted feed content; only the failure category.
            return AdvisoryLoad.failure(AdvisoryLoad.Status.PARSE_ERROR,
                    "verified advisory feed could not be parsed");
        }
        if (feed.schemaVersion() != AdvisoryFeed.SCHEMA_VERSION) {
            return AdvisoryLoad.failure(AdvisoryLoad.Status.UNSUPPORTED_VERSION,
                    "advisory feed schema version " + feed.schemaVersion() + " is unsupported");
        }
        return AdvisoryLoad.loaded(feed);
    }
}
