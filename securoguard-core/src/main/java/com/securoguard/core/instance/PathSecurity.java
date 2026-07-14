package com.securoguard.core.instance;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.regex.Pattern;

/**
 * Security-relevant path checks shared across the engine.
 *
 * <p>Two classes of problem are handled here and are commented individually
 * because getting them wrong defeats the whole tool:
 *
 * <ol>
 *   <li><b>Containment.</b> A file that resolves outside the configured instance
 *       root (after normalization) must never be treated as belonging to the
 *       instance. Attackers use {@code ../} traversal and absolute paths embedded
 *       in archives to reach outside the sandboxed area.</li>
 *   <li><b>Link redirection.</b> Symbolic links and Windows junctions can make a
 *       path inside {@code mods/} physically resolve elsewhere. We do not follow
 *       them silently; callers ask explicitly and we surface the fact.</li>
 * </ol>
 */
public final class PathSecurity {

    // A drive-letter prefix such as "C:" — Windows absolute or drive-relative.
    private static final Pattern DRIVE_PREFIX = Pattern.compile("^[A-Za-z]:.*");

    private PathSecurity() {
    }

    /**
     * Validates that {@code rel} is a genuinely-relative, contained path suitable for
     * {@code root.resolve(rel)} and returns the normalized relative form.
     *
     * <p>This is the authoritative guard used before ever writing to a path derived
     * from untrusted data (a quarantine sidecar's stored relative path, a configured
     * monitored directory). It rejects every way a string can escape {@code root}:
     * <ul>
     *   <li>null / empty / blank</li>
     *   <li>null bytes or other control characters</li>
     *   <li>absolute paths ({@code /foo}, {@code \foo})</li>
     *   <li>drive-qualified paths ({@code C:\foo}, {@code C:foo})</li>
     *   <li>UNC paths ({@code \\host\share}, {@code //host/share})</li>
     *   <li>any {@code ..} traversal segment</li>
     *   <li>anything that, once resolved and normalized, leaves {@code root}</li>
     * </ul>
     *
     * @return the resolved, normalized, contained absolute target
     * @throws SecurityException if {@code rel} is not a safe contained relative path
     */
    public static Path resolveContainedRelative(Path root, String rel) {
        if (rel == null || rel.isBlank()) {
            throw new SecurityException("Relative path is null or blank");
        }
        if (containsControlChars(rel)) {
            throw new SecurityException("Relative path contains control characters or a null byte");
        }
        String norm = rel.replace('\\', '/');
        if (norm.startsWith("/")) {
            throw new SecurityException("Relative path is absolute or UNC: " + rel);
        }
        if (DRIVE_PREFIX.matcher(rel).matches() || rel.contains(":")) {
            throw new SecurityException("Relative path is drive-qualified: " + rel);
        }
        for (String segment : norm.split("/")) {
            if (segment.equals("..")) {
                throw new SecurityException("Relative path contains a traversal segment: " + rel);
            }
        }
        Path base = root.toAbsolutePath().normalize();
        Path resolved = base.resolve(norm).normalize();
        if (!resolved.startsWith(base)) {
            // Belt-and-braces: normalization must not have escaped the root.
            throw new SecurityException("Relative path escapes the root after normalization: " + rel);
        }
        return resolved;
    }

    /**
     * True if {@code name} is a plain basename: no path separators, not {@code .}
     * or {@code ..}, no drive prefix, no control characters, non-empty. Used to
     * validate a quarantine {@code storedFileName}.
     */
    public static boolean isBasename(String name) {
        if (name == null || name.isEmpty() || name.equals(".") || name.equals("..")) {
            return false;
        }
        if (containsControlChars(name)) {
            return false;
        }
        return name.indexOf('/') < 0 && name.indexOf('\\') < 0 && !name.contains(":");
    }

    /**
     * Walks from {@code target} up to (and including) {@code root} and returns
     * {@code true} if any existing component on that chain is a symlink/junction, or
     * if the nearest existing ancestor's real path escapes {@code root}'s real path.
     * A {@code true} result means a restore/write through this path could be
     * redirected outside the instance and must be refused.
     */
    public static boolean hasRedirectedAncestor(Path root, Path target) {
        try {
            Path realRoot = root.toRealPath();
            Path cur = target.toAbsolutePath().normalize();
            // Find the nearest existing ancestor and check every existing link on the way.
            while (cur != null && !cur.equals(realRoot)) {
                if (Files.exists(cur, LinkOption.NOFOLLOW_LINKS)) {
                    if (Files.isSymbolicLink(cur)) {
                        return true;
                    }
                    // Nearest existing ancestor: verify its canonical path stays in root.
                    Path real = cur.toRealPath();
                    return !real.startsWith(realRoot);
                }
                cur = cur.getParent();
            }
            return false;
        } catch (IOException e) {
            // Cannot verify -> treat as redirected (fail safe).
            return true;
        }
    }

    private static boolean containsControlChars(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\0' || (c < 0x20) || c == 0x7F) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code true} iff {@code candidate}, once normalized, is {@code root}
     * or lies underneath it. Purely lexical — it does not touch the filesystem, so
     * it is safe to call on paths that do not exist yet.
     */
    public static boolean isContained(Path root, Path candidate) {
        Path r = root.toAbsolutePath().normalize();
        Path c = candidate.toAbsolutePath().normalize();
        return c.startsWith(r);
    }

    /**
     * Validates that a relative archive entry name does not escape a target
     * directory. Rejects absolute entries and any entry whose resolved location
     * leaves {@code targetDir}. This is the classic "Zip Slip" guard.
     *
     * @return the safe resolved path
     * @throws SecurityException if the entry would escape {@code targetDir}
     */
    public static Path resolveZipEntrySafely(Path targetDir, String entryName) {
        // Reject Windows/Unix absolute-looking names outright.
        if (entryName.startsWith("/") || entryName.startsWith("\\") || entryName.contains(":")) {
            throw new SecurityException("Archive entry uses an absolute path: " + entryName);
        }
        Path base = targetDir.toAbsolutePath().normalize();
        Path resolved = base.resolve(entryName).normalize();
        if (!resolved.startsWith(base)) {
            throw new SecurityException("Archive entry escapes target directory: " + entryName);
        }
        return resolved;
    }

    /**
     * Detects whether a ZIP/JAR entry name contains directory-traversal segments
     * or an absolute prefix. Unlike {@link #resolveZipEntrySafely} this only
     * inspects the string and never throws, so it can be used as a scan predicate.
     */
    public static boolean isTraversalEntryName(String entryName) {
        if (entryName == null || entryName.isEmpty()) {
            return false;
        }
        String normalized = entryName.replace('\\', '/');
        if (normalized.startsWith("/") || normalized.matches("^[A-Za-z]:.*")) {
            return true;
        }
        for (String segment : normalized.split("/")) {
            if (segment.equals("..")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns {@code true} if the path is a symbolic link or (on Windows) a
     * junction/reparse point that redirects elsewhere. Callers treat a positive
     * result as security-relevant rather than following it blindly.
     */
    public static boolean isLinkOrRedirect(Path path) {
        if (Files.isSymbolicLink(path)) {
            return true;
        }
        try {
            // A reparse point (junction) reports a different real path than its
            // lexical normalized form even though isSymbolicLink() may be false.
            if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                return false;
            }
            Path real = path.toRealPath();
            Path lexical = path.toAbsolutePath().normalize();
            return !real.equals(lexical);
        } catch (IOException e) {
            // If we cannot resolve it, err on the side of flagging it.
            return true;
        }
    }
}
