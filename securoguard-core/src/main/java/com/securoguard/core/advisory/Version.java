package com.securoguard.core.advisory;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A dotted version usable for both Minecraft ("1.21.11", "26.2") and mod versions
 * ("0.12.4", "0.22.2-sakura.4", "0.19.0+1.21").
 *
 * <p><b>Validity is explicit.</b> {@link #tryParse(String)} returns empty for a
 * string that is not a well-formed version; advisory matching treats that as a
 * <em>safe non-match</em> rather than silently comparing it as {@code 0}. A
 * well-formed core is one or more dot-separated numeric components, optionally
 * followed by a {@code -prerelease} and/or {@code +build} suffix.
 *
 * <p><b>Prerelease comparison follows SemVer</b> (numeric identifiers compared
 * numerically, not lexicographically): {@code 0.22.2-sakura.4 < 0.22.2-sakura.10 <
 * 0.22.2 < 0.22.5}.
 */
public final class Version implements Comparable<Version> {

    private final List<Integer> numbers;
    private final List<String> preRelease; // dot-separated identifiers; empty if none
    private final String raw;

    private Version(List<Integer> numbers, List<String> preRelease, String raw) {
        this.numbers = numbers;
        this.preRelease = preRelease;
        this.raw = raw;
    }

    /**
     * Parses a version, returning empty for anything not well-formed. Never treats a
     * malformed string as {@code 0}.
     */
    public static Optional<Version> tryParse(String text) {
        if (text == null) {
            return Optional.empty();
        }
        String raw = text.trim();
        if (raw.isEmpty()) {
            return Optional.empty();
        }
        // Strip build metadata after '+' (e.g. "0.19.0+1.21" -> "0.19.0").
        String core = raw;
        int plus = core.indexOf('+');
        if (plus >= 0) {
            core = core.substring(0, plus);
        }
        List<String> pre = new ArrayList<>();
        int dash = core.indexOf('-');
        if (dash >= 0) {
            String preText = core.substring(dash + 1);
            core = core.substring(0, dash);
            if (preText.isEmpty()) {
                return Optional.empty(); // "1.0.0-" is malformed
            }
            for (String id : preText.split("\\.", -1)) {
                if (id.isEmpty()) {
                    return Optional.empty();
                }
                pre.add(id);
            }
        }
        String[] coreParts = core.split("\\.", -1);
        List<Integer> nums = new ArrayList<>();
        for (String part : coreParts) {
            // Every core component must be purely numeric — no "21a", no "mc1".
            if (part.isEmpty() || !isAllDigits(part)) {
                return Optional.empty();
            }
            try {
                nums.add(Integer.parseInt(part));
            } catch (NumberFormatException e) {
                return Optional.empty(); // overflow etc.
            }
        }
        if (nums.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new Version(nums, pre, raw));
    }

    /**
     * Lenient parse for <em>trusted</em>, known-valid strings (e.g. feed bounds
     * authored by maintainers). Throws {@link IllegalArgumentException} on a
     * malformed string so a bad feed is a loud error, never a silent zero.
     */
    public static Version parse(String text) {
        return tryParse(text).orElseThrow(
                () -> new IllegalArgumentException("Malformed version: " + text));
    }

    @Override
    public int compareTo(Version other) {
        int len = Math.max(numbers.size(), other.numbers.size());
        for (int i = 0; i < len; i++) {
            int a = i < numbers.size() ? numbers.get(i) : 0;
            int b = i < other.numbers.size() ? other.numbers.get(i) : 0;
            if (a != b) {
                return Integer.compare(a, b);
            }
        }
        // Equal numeric core: a prerelease ranks below the same plain release.
        boolean aPre = !preRelease.isEmpty();
        boolean bPre = !other.preRelease.isEmpty();
        if (aPre != bPre) {
            return aPre ? -1 : 1;
        }
        if (!aPre) {
            return 0;
        }
        return comparePreRelease(preRelease, other.preRelease);
    }

    /** SemVer §11.4 precedence for prerelease identifier lists. */
    private static int comparePreRelease(List<String> a, List<String> b) {
        int len = Math.min(a.size(), b.size());
        for (int i = 0; i < len; i++) {
            String ida = a.get(i);
            String idb = b.get(i);
            boolean na = isAllDigits(ida);
            boolean nb = isAllDigits(idb);
            if (na && nb) {
                int cmp = Long.compare(Long.parseLong(ida), Long.parseLong(idb));
                if (cmp != 0) {
                    return cmp;
                }
            } else if (na != nb) {
                // Numeric identifiers always have lower precedence than alphanumeric.
                return na ? -1 : 1;
            } else {
                int cmp = ida.compareTo(idb);
                if (cmp != 0) {
                    return cmp;
                }
            }
        }
        // All shared identifiers equal: the shorter set has lower precedence.
        return Integer.compare(a.size(), b.size());
    }

    private static boolean isAllDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    public String raw() {
        return raw;
    }

    @Override
    public String toString() {
        return raw;
    }
}
