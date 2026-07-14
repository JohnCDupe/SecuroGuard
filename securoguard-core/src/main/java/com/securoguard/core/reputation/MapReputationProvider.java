package com.securoguard.core.reputation;

import com.securoguard.core.util.HashAlgorithm;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Deterministic, offline reputation provider backed by an in-memory map. This is
 * the default provider: SecuroGuard is fully functional with no network access.
 * It is also the provider used by tests, so reputation-dependent behaviour is
 * reproducible without contacting any service.
 *
 * <p>The algorithm defaults to SHA-512 (matching the real Modrinth provider) so a
 * test can register a file's SHA-512 and see it recognised through the same path
 * production uses.
 */
public final class MapReputationProvider implements HashReputationProvider {

    private final HashAlgorithm algorithm;
    private final Map<String, ReputationResult> known = new HashMap<>();

    public MapReputationProvider() {
        this(HashAlgorithm.SHA512);
    }

    public MapReputationProvider(HashAlgorithm algorithm) {
        this.algorithm = algorithm;
    }

    /** Registers a hash (of {@link #requiredAlgorithm()}) as recognised on a platform. */
    public MapReputationProvider addKnown(String hex, String project, String version) {
        known.put(hex.toLowerCase(Locale.ROOT), ReputationResult.known(hex, project, version));
        return this;
    }

    @Override
    public String name() {
        return "test";
    }

    @Override
    public HashAlgorithm requiredAlgorithm() {
        return algorithm;
    }

    @Override
    public ReputationResult lookup(String hex) {
        if (hex == null) {
            return ReputationResult.unavailable("");
        }
        String key = hex.toLowerCase(Locale.ROOT);
        return known.getOrDefault(key, ReputationResult.unknown(key));
    }
}
