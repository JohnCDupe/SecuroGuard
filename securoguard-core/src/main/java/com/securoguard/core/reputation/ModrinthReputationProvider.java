package com.securoguard.core.reputation;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.securoguard.core.util.HashAlgorithm;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Optional online provider that looks up a hash against Modrinth's public
 * {@code version_file} API.
 *
 * <p><b>Correctness (R3):</b> Modrinth's {@code /v2/version_file/{hash}} endpoint
 * only supports {@code sha1} and {@code sha512} — <em>not</em> sha256. This provider
 * therefore requires a <b>SHA-512</b> hash and requests {@code ?algorithm=sha512}.
 *
 * <p>Compliant with Modrinth's documented usage: hash-only requests, a descriptive
 * User-Agent, short timeouts, rate-limit backoff, local caching, and fail-open
 * behaviour (any error → {@link ReputationStatus#LOOKUP_UNAVAILABLE}, never throws).
 * No API key is used or stored, and no file contents are ever uploaded.
 *
 * <p>The {@link HttpTransport} and clock are injectable so this is fully unit-tested
 * without touching the network.
 */
public final class ModrinthReputationProvider implements HashReputationProvider {

    private static final String ENDPOINT = "https://api.modrinth.com/v2/version_file/";
    // Modrinth asks for a descriptive User-Agent with project contact information.
    // Hash-only requests carry no user-identifying data.
    private static final String USER_AGENT =
            "SecuroGuard (Minecraft integrity monitor; +https://github.com/JohnCDupe/SecuroGuard)";

    private final HttpTransport transport;
    private final LongSupplier clock;
    private final Map<String, ReputationResult> cache = new ConcurrentHashMap<>();
    private final AtomicLong backoffUntilMillis = new AtomicLong(0);

    public ModrinthReputationProvider() {
        this(new JdkHttpTransport(), System::currentTimeMillis);
    }

    public ModrinthReputationProvider(HttpTransport transport, LongSupplier clock) {
        this.transport = transport;
        this.clock = clock;
    }

    @Override
    public String name() {
        return "modrinth";
    }

    @Override
    public HashAlgorithm requiredAlgorithm() {
        return HashAlgorithm.SHA512;
    }

    @Override
    public ReputationResult lookup(String sha512Hex) {
        // Validate the hash BEFORE constructing any request. A malformed hash is a
        // programming error, not a reason to hit the network.
        if (sha512Hex == null || !HashAlgorithm.SHA512.isValidHex(sha512Hex)) {
            return ReputationResult.unavailable(sha512Hex == null ? "" : sha512Hex);
        }
        String hex = sha512Hex.toLowerCase(Locale.ROOT);

        ReputationResult cached = cache.get(hex);
        if (cached != null) {
            return cached;
        }
        if (clock.getAsLong() < backoffUntilMillis.get()) {
            return ReputationResult.unavailable(hex); // in rate-limit cool-down
        }
        try {
            // hex is validated [0-9a-f]{128}, so it is safe in the path with no encoding needed.
            URI uri = URI.create(ENDPOINT + hex + "?algorithm=" + HashAlgorithm.SHA512.queryName());
            HttpTransport.Response response = transport.get(uri,
                    Map.of("User-Agent", USER_AGENT, "Accept", "application/json"),
                    Duration.ofSeconds(4));
            ReputationResult result = interpret(hex, response);
            if (result.status() != ReputationStatus.LOOKUP_UNAVAILABLE) {
                cache.put(hex, result); // cache only definitive answers
            }
            return result;
        } catch (Exception e) {
            // Fail-open: offline / DNS / TLS / interruption all become "unavailable".
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return ReputationResult.unavailable(hex);
        }
    }

    private ReputationResult interpret(String hex, HttpTransport.Response response) {
        int code = response.statusCode();
        if (code == 200) {
            try {
                JsonObject obj = JsonParser.parseString(response.body()).getAsJsonObject();
                String version = obj.has("version_number") ? obj.get("version_number").getAsString() : null;
                String project = obj.has("project_id") ? obj.get("project_id").getAsString() : null;
                return ReputationResult.known(hex, project, version);
            } catch (RuntimeException e) {
                return ReputationResult.unavailable(hex); // malformed JSON
            }
        }
        if (code == 404) {
            return ReputationResult.unknown(hex);
        }
        if (code == 429) {
            long retryAfter = response.firstHeaderLong("Retry-After").orElse(60L);
            backoffUntilMillis.set(clock.getAsLong() + Math.max(1, retryAfter) * 1000L);
            return ReputationResult.unavailable(hex);
        }
        return ReputationResult.unavailable(hex);
    }
}
