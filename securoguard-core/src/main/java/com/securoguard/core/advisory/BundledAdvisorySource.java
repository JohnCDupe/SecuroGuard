package com.securoguard.core.advisory;

/**
 * The advisory feed shipped inside the SecuroGuard jar. Trusted because it is part
 * of the (release-signed) artifact itself — no network, no external input. Parsed
 * once and cached.
 */
public final class BundledAdvisorySource implements AdvisorySource {

    private volatile AdvisoryLoad cached;

    @Override
    public AdvisoryLoad load() {
        AdvisoryLoad local = cached;
        if (local == null) {
            synchronized (this) {
                if (cached == null) {
                    try {
                        cached = AdvisoryLoad.loaded(AdvisoryFeeds.bundledFeed());
                    } catch (RuntimeException e) {
                        // A broken bundle is a build defect; surface it as degraded, never crash.
                        cached = AdvisoryLoad.failure(AdvisoryLoad.Status.PARSE_ERROR,
                                "bundled feed unreadable: " + e.getMessage());
                    }
                }
                local = cached;
            }
        }
        return local;
    }
}
