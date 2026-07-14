package com.securoguard.core.service;

import com.securoguard.core.inventory.ScanLimits;
import com.securoguard.core.util.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * User-tunable settings, loaded from {@code config/securoguard.json} if present.
 * Every field has a safe default so SecuroGuard works with no config at all.
 * Nothing here is a secret — access tokens and credentials are never stored.
 *
 * <p>All numeric values are validated and clamped to safe ranges on load
 * ({@link #validated()}); an out-of-range value is corrected rather than trusted,
 * and the correction is reported via {@link #warnings()}.
 */
public final class SecuroGuardConfig {

    /** Whether to consult an online hash-reputation provider. Off by default (offline-first). */
    public boolean onlineReputationEnabled = false;

    /** Whether the quarantine action is offered in the Fabric UI. Sentinel quarantine is separate. */
    public boolean quarantineEnabled = true;

    /** Extra SHA-256 hashes to treat as known-malicious (lowercase hex). */
    public List<String> knownMaliciousHashes = new ArrayList<>();

    /** Additional instance-relative directories to monitor/scan (beyond mods). */
    public List<String> monitoredDirectories = new ArrayList<>();

    /** Milliseconds a file must be unchanged before the monitor scans it. */
    public long watchQuietPeriodMillis = 1000;

    /** Milliseconds between periodic reconciliation scans. */
    public long reconcileIntervalMillis = 30_000;

    /** Maximum number of files a scan will inventory. */
    public int maxScannedFiles = 200_000;

    /** Files larger than this (bytes) are reported as skipped rather than hashed. */
    public long maxScannedFileSizeBytes = 512L * 1024 * 1024;

    private final transient List<String> warnings = new ArrayList<>();

    /** Corrections applied to out-of-range values on load (for surfacing to the user). */
    public List<String> warnings() {
        return warnings;
    }

    public ScanLimits scanLimits() {
        return new ScanLimits(maxScannedFiles, maxScannedFileSizeBytes);
    }

    /** Loads config from the given file, or returns validated defaults if absent/invalid. */
    public static SecuroGuardConfig loadOrDefault(Path configFile) {
        try {
            if (Files.isRegularFile(configFile)) {
                String json = Files.readString(configFile, StandardCharsets.UTF_8);
                SecuroGuardConfig cfg = Json.gson().fromJson(json, SecuroGuardConfig.class);
                if (cfg != null) {
                    return cfg.validated();
                }
            }
        } catch (IOException | RuntimeException e) {
            // Fall back to defaults on any problem; a bad config must not brick startup.
        }
        return new SecuroGuardConfig();
    }

    /**
     * Returns this config with every value validated and clamped to a safe range.
     * Dangerous or nonsensical values are corrected (and recorded in {@link #warnings()})
     * instead of being silently accepted.
     */
    public SecuroGuardConfig validated() {
        if (knownMaliciousHashes == null) {
            knownMaliciousHashes = new ArrayList<>();
        }
        if (monitoredDirectories == null) {
            monitoredDirectories = new ArrayList<>();
        }
        watchQuietPeriodMillis = clampLong("watchQuietPeriodMillis", watchQuietPeriodMillis, 100, 60_000, 1000);
        reconcileIntervalMillis = clampLong("reconcileIntervalMillis", reconcileIntervalMillis, 1000, 3_600_000, 30_000);
        maxScannedFiles = (int) clampLong("maxScannedFiles", maxScannedFiles, 1, 5_000_000, 200_000);
        maxScannedFileSizeBytes = clampLong("maxScannedFileSizeBytes", maxScannedFileSizeBytes,
                1024, 8L * 1024 * 1024 * 1024, 512L * 1024 * 1024);
        return this;
    }

    private long clampLong(String name, long value, long min, long max, long fallback) {
        if (value < min || value > max) {
            long corrected = value < min ? min : max;
            warnings.add("config '" + name + "'=" + value + " out of range [" + min + ", " + max
                    + "]; using " + corrected);
            return corrected;
        }
        return value;
    }
}
