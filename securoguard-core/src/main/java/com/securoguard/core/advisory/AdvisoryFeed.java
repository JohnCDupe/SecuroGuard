package com.securoguard.core.advisory;

import com.securoguard.core.util.Json;

import java.util.List;

/**
 * A parsed advisory feed. Parsing ({@link #fromJson}) is deliberately decoupled
 * from downloading: this class only ever consumes bytes the caller already has and
 * has (ideally) already signature-verified. There is no remote update mechanism
 * here — see {@code docs/advisory-format.md} for the planned signed-feed rollout.
 */
public record AdvisoryFeed(int schemaVersion, long generatedAtMillis, List<Advisory> advisories) {

    public static final int SCHEMA_VERSION = 1;

    public static AdvisoryFeed fromJson(String json) {
        AdvisoryFeed feed = Json.gson().fromJson(json, AdvisoryFeed.class);
        if (feed == null || feed.advisories == null) {
            throw new IllegalArgumentException("Advisory feed is empty or malformed");
        }
        return feed;
    }

    public static AdvisoryFeed empty() {
        return new AdvisoryFeed(SCHEMA_VERSION, 0L, List.of());
    }
}
