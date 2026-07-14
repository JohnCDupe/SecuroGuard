package com.securoguard.core.advisory;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Loads the advisory feed bundled inside the SecuroGuard jar. This is authoritative
 * production data (not a "sample"): the Litematica/Servux advisories used by real
 * scans. There is deliberately no network fetch here — a signed remote feed is a
 * future milestone (see {@code docs/advisory-format.md}).
 */
public final class AdvisoryFeeds {

    private static final String BUNDLED_RESOURCE = "/com/securoguard/core/advisory/securoguard-advisories.json";

    private AdvisoryFeeds() {
    }

    /** Reads the bundled feed's raw JSON bytes (the bytes a signature would cover). */
    public static byte[] bundledFeedBytes() {
        try (InputStream in = AdvisoryFeeds.class.getResourceAsStream(BUNDLED_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Bundled advisory feed not found on classpath");
            }
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Parses the bundled advisory feed. */
    public static AdvisoryFeed bundledFeed() {
        return AdvisoryFeed.fromJson(new String(bundledFeedBytes(), StandardCharsets.UTF_8));
    }
}
