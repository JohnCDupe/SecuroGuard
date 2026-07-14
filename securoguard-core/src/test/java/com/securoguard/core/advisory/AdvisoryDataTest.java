package com.securoguard.core.advisory;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RB1: table-driven verification of the bundled Litematica/Servux advisory data —
 * every Minecraft line, both mods, with correct affected/fixed/introduced boundaries
 * and no cross-mod contamination.
 */
class AdvisoryDataTest {

    private static final AdvisoryMatcher MATCHER = new AdvisoryMatcher(AdvisoryFeeds.bundledFeed());

    private List<Advisory> match(String mod, String mc, String version) {
        return MATCHER.match(new AdvisoryMatcher.Query(mod, "fabric", mc, version, null));
    }

    /** mod, minecraft, lastAffected, fixed, later, preIntro(nullable). */
    static Stream<Arguments> lines() {
        return Stream.of(
                // Litematica — introduction bound known for 1.21..1.21.5.
                Arguments.of("litematica", "1.21", "0.19.60", "0.19.61", "0.20.0", "0.19.59"),
                Arguments.of("litematica", "1.21.2", "0.20.8", "0.20.9", "0.21.0", "0.20.7"),
                Arguments.of("litematica", "1.21.4", "0.21.6", "0.21.7", "0.22.0", "0.21.5"),
                Arguments.of("litematica", "1.21.5", "0.22.4", "0.22.5", "0.23.0", "0.22.2-sakura.3"),
                // Litematica — 1.21.6+ lower bound is conservatively unbounded (no preIntro).
                Arguments.of("litematica", "1.21.6", "0.23.6", "0.23.7", "0.24.0", null),
                Arguments.of("litematica", "1.21.9", "0.24.7", "0.24.8", "0.25.0", null),
                Arguments.of("litematica", "1.21.11", "0.26.10", "0.26.11", "0.27.0", null),
                Arguments.of("litematica", "26.1", "0.27.8", "0.27.9", "0.28.0", null),
                Arguments.of("litematica", "26.2", "0.28.2", "0.28.3", "0.29.0", null),
                // Servux — lower bound conservatively unbounded on every line.
                Arguments.of("servux", "1.21", "0.3.16", "0.3.17", "0.4.0", null),
                Arguments.of("servux", "1.21.2", "0.4.7", "0.4.8", "0.5.0", null),
                Arguments.of("servux", "1.21.4", "0.5.6", "0.5.7", "0.6.0", null),
                Arguments.of("servux", "1.21.5", "0.6.3", "0.6.4", "0.7.0", null),
                Arguments.of("servux", "1.21.6", "0.7.6", "0.7.7", "0.8.0", null),
                Arguments.of("servux", "1.21.9", "0.8.6", "0.8.7", "0.9.0", null),
                Arguments.of("servux", "1.21.11", "0.9.4", "0.9.5", "0.10.0", null),
                Arguments.of("servux", "26.1", "0.10.3", "0.10.4", "0.11.0", null),
                Arguments.of("servux", "26.2", "0.11.1", "0.11.2", "0.12.0", null));
    }

    @ParameterizedTest(name = "{0} on MC {1}")
    @MethodSource("lines")
    void boundariesPerLine(String mod, String mc, String lastAffected, String fixed,
                           String later, String preIntro) {
        // Last affected release: exactly one advisory, no duplicates.
        List<Advisory> affected = match(mod, mc, lastAffected);
        assertEquals(1, affected.size(), mod + " " + lastAffected + " on " + mc + " should be flagged once");
        assertTrue(affected.get(0).modIds().contains(mod), "advisory must be for the right mod");

        // Fixed release: not flagged.
        assertTrue(match(mod, mc, fixed).isEmpty(), mod + " " + fixed + " (fixed) must not be flagged");
        // Later release: not flagged.
        assertTrue(match(mod, mc, later).isEmpty(), mod + " " + later + " (later) must not be flagged");
        // Pre-introduction release (where the lower bound is known): not flagged.
        if (preIntro != null) {
            assertTrue(match(mod, mc, preIntro).isEmpty(),
                    mod + " " + preIntro + " predates the vulnerable feature and must not be flagged");
        }
    }

    @Test
    void prereleaseComparisonIsNumericNotLexicographic() {
        // MC 1.21.5 Litematica: affected [0.22.2-sakura.4, 0.22.5).
        assertEquals(1, match("litematica", "1.21.5", "0.22.2-sakura.4").size(), "== introduced is affected");
        assertEquals(1, match("litematica", "1.21.5", "0.22.2-sakura.10").size(),
                "sakura.10 > sakura.4 numerically (not lexicographically)");
        assertEquals(1, match("litematica", "1.21.5", "0.22.2").size(), "release > its own prereleases, < fixed");
        assertTrue(match("litematica", "1.21.5", "0.22.5").isEmpty(), "fixed is not affected");
        assertTrue(match("litematica", "1.21.5", "0.22.2-sakura.3").isEmpty(),
                "sakura.3 < introduced sakura.4 => not affected");
    }

    @Test
    void modsDoNotCrossContaminate() {
        // A patched Servux version is never flagged (and never checked against Litematica bounds).
        assertTrue(match("servux", "1.21.11", "0.9.5").isEmpty(), "patched Servux must not match anything");
        // A Litematica-style version number under the servux id uses the SERVUX boundary (0.9.5),
        // so 0.26.10 (>= 0.9.5) is NOT flagged — proving Servux is not checked against Litematica's range.
        assertTrue(match("servux", "1.21.11", "0.26.10").isEmpty(),
                "Servux must use its own boundary, not Litematica's");
        // A fixed Litematica version is not flagged and is never checked against Servux bounds.
        assertTrue(match("litematica", "1.21.11", "0.26.11").isEmpty(), "patched Litematica must not match");
        // Litematica advisories only list litematica; Servux advisories only list servux.
        for (Advisory a : AdvisoryFeeds.bundledFeed().advisories()) {
            assertEquals(1, a.modIds().size(), "each advisory targets exactly one mod: " + a.id());
        }
    }

    @Test
    void disclosureDateAndSeparationMetadata() {
        List<Advisory> all = AdvisoryFeeds.bundledFeed().advisories();
        assertEquals(18, all.size(), "9 Minecraft lines x 2 mods");
        // 2026-07-06 disclosure, not an arbitrary July-1 placeholder.
        long jul6 = 1783296000000L;
        assertTrue(all.stream().allMatch(a -> a.publishedAtMillis() == jul6),
                "published date should be the 2026-07-06 disclosure date");
        assertEquals(9, all.stream().filter(a -> a.modIds().contains("litematica")).count());
        assertEquals(9, all.stream().filter(a -> a.modIds().contains("servux")).count());
    }
}
