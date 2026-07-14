package com.securoguard.core.jar;

/**
 * Distinct categories of problem an inspection can surface. Keeping these separate
 * (rather than one undifferentiated "problem" bucket) lets rules and the UI react
 * appropriately — a malformed archive is a different signal from a zip bomb, which
 * is different again from a traversal entry.
 */
public enum ArchiveIssue {
    /** The bytes are not a valid ZIP, or the central directory / an entry failed to parse. */
    MALFORMED,
    /** A defensive limit (size, entry count, ratio, depth, time, memory) was hit. */
    LIMIT_EXCEEDED,
    /** At least one entry name attempts directory traversal. */
    TRAVERSAL_ENTRY,
    /** The archive uses a feature we intentionally do not process (e.g. encryption). */
    UNSUPPORTED_FEATURE
}
