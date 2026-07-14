package com.securoguard.core.advisory;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Matches installed mods against a feed. Two independent match paths:
 * <ol>
 *   <li><b>Hash match.</b> If a file's SHA-256 is in an advisory's {@code knownHashes},
 *       it matches regardless of coordinates — the strongest signal.</li>
 *   <li><b>Coordinate match.</b> mod id + loader + Minecraft version + mod version all
 *       falling within the advisory's declared ranges.</li>
 * </ol>
 *
 * <p><b>No guessing (RB2).</b> If an advisory constrains the loader or Minecraft
 * version and the query does not supply that coordinate, coordinate matching does
 * <em>not</em> occur — SecuroGuard never matches a mod against unrelated
 * Minecraft-line advisories just because the version was unknown. Such cases are
 * reported once via {@link MatchResult#incomplete()} so the caller can surface a
 * single "advisory matching incomplete" notice. Malformed versions are safe
 * non-matches, never treated as {@code 0}.
 */
public final class AdvisoryMatcher {

    /** A query describing one installed mod (any field may be null/unknown). */
    public record Query(String modId, String loader, String minecraftVersion,
                        String modVersion, String sha256) {
    }

    /** Which required coordinate was missing, blocking a relevant coordinate advisory. */
    public enum Incomplete {
        LOADER_UNKNOWN,
        MINECRAFT_VERSION_UNKNOWN
    }

    /** Result of evaluating one query: the matched advisories plus any incompleteness. */
    public record MatchResult(List<Advisory> matches, EnumSet<Incomplete> incomplete) {
    }

    private final AdvisoryFeed feed;

    public AdvisoryMatcher(AdvisoryFeed feed) {
        this.feed = feed;
    }

    /** Backward-compatible convenience: just the matched advisories. */
    public List<Advisory> match(Query q) {
        return evaluate(q).matches();
    }

    /** Full evaluation, including which required coordinates were missing. */
    public MatchResult evaluate(Query q) {
        List<Advisory> matches = new ArrayList<>();
        EnumSet<Incomplete> incomplete = EnumSet.noneOf(Incomplete.class);
        for (Advisory a : feed.advisories()) {
            if (matchesHash(a, q)) {
                if (!matches.contains(a)) {
                    matches.add(a);
                }
                continue;
            }
            switch (coordinateOutcome(a, q, incomplete)) {
                case MATCH -> {
                    if (!matches.contains(a)) {
                        matches.add(a);
                    }
                }
                case NO_MATCH, NOT_RELEVANT -> { /* nothing */ }
            }
        }
        return new MatchResult(matches, incomplete);
    }

    private enum Outcome {MATCH, NO_MATCH, NOT_RELEVANT}

    private Outcome coordinateOutcome(Advisory a, Query q, EnumSet<Incomplete> incomplete) {
        if (q.modId() == null || a.modIds() == null || a.modIds().isEmpty()
                || !containsIgnoreCase(a.modIds(), q.modId())) {
            return Outcome.NOT_RELEVANT; // this advisory is not about this mod
        }
        // From here the advisory IS about this mod, so a missing required coordinate
        // is an "incomplete" situation, not merely a non-match.

        boolean constrainsLoader = a.loader() != null && !a.loader().isBlank();
        if (constrainsLoader) {
            if (q.loader() == null || q.loader().isBlank()) {
                incomplete.add(Incomplete.LOADER_UNKNOWN);
                return Outcome.NO_MATCH; // never guess
            }
            if (!a.loader().equalsIgnoreCase(q.loader())) {
                return Outcome.NO_MATCH;
            }
        }

        boolean constrainsMc = a.minecraftRange() != null
                && ((a.minecraftRange().introduced() != null && !a.minecraftRange().introduced().isBlank())
                    || (a.minecraftRange().fixed() != null && !a.minecraftRange().fixed().isBlank()));
        if (constrainsMc) {
            if (q.minecraftVersion() == null || q.minecraftVersion().isBlank()) {
                incomplete.add(Incomplete.MINECRAFT_VERSION_UNKNOWN);
                return Outcome.NO_MATCH; // never guess
            }
            Optional<Version> mc = Version.tryParse(q.minecraftVersion());
            if (mc.isEmpty() || !a.minecraftRange().contains(mc.get())) {
                return Outcome.NO_MATCH; // malformed or out-of-line => safe non-match
            }
        }

        // Mod-version check.
        if (a.affectedRanges() == null || a.affectedRanges().isEmpty()) {
            return Outcome.MATCH; // any version of the named mod on this loader/line
        }
        Optional<Version> mv = Version.tryParse(q.modVersion());
        if (mv.isEmpty()) {
            return Outcome.NO_MATCH; // null or malformed mod version => safe non-match
        }
        for (VersionRange range : a.affectedRanges()) {
            if (range != null && range.contains(mv.get())) {
                return Outcome.MATCH;
            }
        }
        return Outcome.NO_MATCH;
    }

    private boolean matchesHash(Advisory a, Query q) {
        if (q.sha256() == null || a.knownHashes() == null) {
            return false;
        }
        String h = q.sha256().toLowerCase(Locale.ROOT);
        for (String known : a.knownHashes()) {
            if (known != null && known.toLowerCase(Locale.ROOT).equals(h)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsIgnoreCase(List<String> list, String value) {
        for (String s : list) {
            if (s != null && s.equalsIgnoreCase(value)) {
                return true;
            }
        }
        return false;
    }
}
