package com.securoguard.core.reputation;

import com.securoguard.core.util.HashAlgorithm;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Abstraction over a hosting-platform hash-reputation service. Implementations
 * must be <em>hash-only</em>: they may send file hashes, never file contents.
 *
 * <p>The algorithm is explicit ({@link #requiredAlgorithm()}) rather than an
 * ambiguous string: a provider states which hash it needs (Modrinth needs
 * SHA-512), and the caller supplies exactly that hash to {@link #lookup(String)}.
 *
 * <p>Every implementation must degrade gracefully: a network failure returns
 * {@link ReputationStatus#LOOKUP_UNAVAILABLE} and never throws in a way that would
 * block Minecraft from starting or a Sentinel scan from completing.
 */
public interface HashReputationProvider {

    /** Short, stable identifier used in logs and findings (e.g. "modrinth", "test"). */
    String name();

    /** The hash algorithm this provider expects {@link #lookup(String)} to receive. */
    HashAlgorithm requiredAlgorithm();

    /**
     * Looks up a single lowercase-hex hash of {@link #requiredAlgorithm()}. Never
     * throws; returns a result (including for malformed input).
     */
    ReputationResult lookup(String hex);

    /** Batch convenience keyed by the supplied hex. */
    default Map<String, ReputationResult> lookupAll(Collection<String> hexes) {
        LinkedHashMap<String, ReputationResult> out = new LinkedHashMap<>();
        for (String h : hexes) {
            out.put(h, lookup(h));
        }
        return out;
    }
}
