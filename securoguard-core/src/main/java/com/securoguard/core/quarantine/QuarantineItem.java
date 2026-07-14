package com.securoguard.core.quarantine;

import java.util.List;

/**
 * Sidecar metadata describing one quarantined file. Persisted next to the stored
 * blob as {@code <stored>.json}. Records exactly what was moved, from where, its
 * verified hash, and which findings triggered the action — so a human can audit or
 * restore it later.
 */
public record QuarantineItem(
        int schemaVersion,
        String id,
        String originalAbsolutePath,
        String originalRelativePath,
        String originalFileName,
        String storedFileName,
        String sha256,
        long size,
        long quarantinedAtMillis,
        List<TriggeringFinding> triggeringFindings) {

    public static final int SCHEMA_VERSION = 1;

    /** A compact, human-readable record of why a file was quarantined. */
    public record TriggeringFinding(String ruleId, String severity, String title) {
    }
}
