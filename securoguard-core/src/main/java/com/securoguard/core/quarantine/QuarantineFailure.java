package com.securoguard.core.quarantine;

/**
 * Recoverable evidence written when a quarantine operation moved a file but then
 * failed post-move verification (R8). The moved file is the only remaining copy, so
 * it is preserved as an "orphan" alongside this record rather than being deleted or
 * silently returned to {@code mods}. {@link QuarantineManager#listFailures()}
 * surfaces these for manual recovery.
 *
 * @param originalRelativePath instance-relative path the file came from
 * @param destinationPath      where the (unindexed) moved file now lives
 * @param expectedSha256       the source hash we expected
 * @param observedSha256       the hash actually observed at the destination
 * @param failureStage         which step failed (e.g. "post-move-verify")
 */
public record QuarantineFailure(
        int schemaVersion,
        String id,
        String originalRelativePath,
        String storedFileName,
        String destinationPath,
        String expectedSha256,
        String observedSha256,
        long failedAtMillis,
        String failureStage) {

    public static final int SCHEMA_VERSION = 1;
}
