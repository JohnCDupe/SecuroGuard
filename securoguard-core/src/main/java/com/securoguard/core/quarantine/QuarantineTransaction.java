package com.securoguard.core.quarantine;

/**
 * A durable "PREPARED" record written <em>before</em> a quarantine move (Phase 1D).
 * It makes quarantine transactional: if any step fails after the source has moved —
 * including a failure to hash the destination or to write the normal sidecar — this
 * record remains on disk so {@link QuarantineManager#listFailures()} can still find
 * the orphaned file. On success the record is finalized (removed).
 *
 * @param originalRelativePath validated instance-relative source path
 * @param storedFileName       intended destination basename inside the quarantine dir
 * @param expectedSha256       the source hash computed before the move
 * @param size                 the source size in bytes
 * @param preparedAtMillis     when the transaction was prepared
 */
public record QuarantineTransaction(
        int schemaVersion,
        String id,
        String originalRelativePath,
        String storedFileName,
        String expectedSha256,
        long size,
        long preparedAtMillis) {

    public static final int SCHEMA_VERSION = 1;
}
