package com.securoguard.core.advisory;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RB2: coordinate matching must never guess. Missing constrained coordinates
 * (Minecraft version, loader) produce no coordinate match and are reported once via
 * {@link AdvisoryMatcher.MatchResult#incomplete()}. Malformed versions are safe
 * non-matches. Known-hash matching remains independent of coordinates.
 */
class AdvisoryMatchingSemanticsTest {

    private final AdvisoryMatcher matcher = new AdvisoryMatcher(AdvisoryFeeds.bundledFeed());

    @Test
    void missingMinecraftVersionProducesNoCoordinateMatch() {
        var result = matcher.evaluate(new AdvisoryMatcher.Query(
                "litematica", "fabric", null, "0.26.10", null));
        assertTrue(result.matches().isEmpty(), "must not guess the Minecraft line");
        assertTrue(result.incomplete().contains(AdvisoryMatcher.Incomplete.MINECRAFT_VERSION_UNKNOWN));
    }

    @Test
    void missingConstrainedLoaderProducesNoCoordinateMatch() {
        var result = matcher.evaluate(new AdvisoryMatcher.Query(
                "litematica", null, "1.21.11", "0.26.10", null));
        assertTrue(result.matches().isEmpty());
        assertTrue(result.incomplete().contains(AdvisoryMatcher.Incomplete.LOADER_UNKNOWN));
    }

    @Test
    void litematicaVersionDoesNotMatchOtherMinecraftLines() {
        // 0.26.10 is affected on 1.21.11 but NOT on the 1.21.4 line (fixed 0.21.7).
        assertTrue(matcher.match(new AdvisoryMatcher.Query(
                "litematica", "fabric", "1.21.4", "0.26.10", null)).isEmpty());
    }

    @Test
    void malformedMinecraftVersionIsSafeNonMatch() {
        var result = matcher.evaluate(new AdvisoryMatcher.Query(
                "litematica", "fabric", "not-a-version", "0.26.10", null));
        assertTrue(result.matches().isEmpty());
        // Malformed (not merely missing) is a definite non-match, not an "incomplete" state.
        assertTrue(result.incomplete().isEmpty());
    }

    @Test
    void malformedModVersionIsSafeNonMatch() {
        assertTrue(matcher.match(new AdvisoryMatcher.Query(
                "litematica", "fabric", "1.21.11", "garbage-version", null)).isEmpty());
    }

    @Test
    void knownHashMatchesWithoutAnyCoordinates() {
        // A feed with a hash-only advisory (no mod id, no ranges).
        String json = "{\"schemaVersion\":1,\"generatedAtMillis\":0,\"advisories\":[{"
                + "\"id\":\"SG-HASH-1\",\"modIds\":[],\"loader\":null,\"minecraftRange\":null,"
                + "\"affectedRanges\":[],\"fixedVersions\":[],\"severity\":\"CRITICAL\","
                + "\"references\":[],\"knownHashes\":[\"abc123\"],\"publishedAtMillis\":0,\"updatedAtMillis\":0}]}";
        AdvisoryMatcher m = new AdvisoryMatcher(AdvisoryFeed.fromJson(json));
        var result = m.evaluate(new AdvisoryMatcher.Query(null, null, null, null, "ABC123"));
        assertEquals(1, result.matches().size(), "hash match is independent of coordinates");
        assertTrue(result.incomplete().isEmpty());
    }
}
