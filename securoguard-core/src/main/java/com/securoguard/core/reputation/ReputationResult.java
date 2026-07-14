package com.securoguard.core.reputation;

import java.util.Optional;

/**
 * Result of a single hash lookup: a {@link ReputationStatus} plus, when known, the
 * hosting-platform project/version the hash maps to (for display only).
 */
public record ReputationResult(
        String sha256,
        ReputationStatus status,
        String projectName,
        String versionName) {

    public static ReputationResult unknown(String sha256) {
        return new ReputationResult(sha256, ReputationStatus.UNKNOWN, null, null);
    }

    public static ReputationResult unavailable(String sha256) {
        return new ReputationResult(sha256, ReputationStatus.LOOKUP_UNAVAILABLE, null, null);
    }

    public static ReputationResult known(String sha256, String project, String version) {
        return new ReputationResult(sha256, ReputationStatus.KNOWN_ON_PLATFORM, project, version);
    }

    public Optional<String> projectNameOpt() {
        return Optional.ofNullable(projectName);
    }
}
