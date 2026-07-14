package com.securoguard.core.reputation;

import com.securoguard.core.util.HashAlgorithm;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class ModrinthReputationProviderTest {

    /** A valid-looking SHA-512 hex (128 chars) for a harmless input. */
    private static final String SHA512 = Hashing.sha512("abc".getBytes(StandardCharsets.UTF_8));

    /** Scriptable transport that records the requested URI and counts calls. */
    static final class FakeTransport implements HttpTransport {
        final AtomicReference<URI> lastUri = new AtomicReference<>();
        final AtomicInteger calls = new AtomicInteger();
        volatile Response next;
        volatile IOException toThrow;

        @Override
        public Response get(URI uri, Map<String, String> headers, Duration timeout) throws IOException {
            calls.incrementAndGet();
            lastUri.set(uri);
            if (toThrow != null) {
                throw toThrow;
            }
            return next;
        }
    }

    private ModrinthReputationProvider provider(FakeTransport t, AtomicLong clock) {
        return new ModrinthReputationProvider(t, clock::get);
    }

    @Test
    void hashVectorsAreCorrect() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Hashing.sha256("abc".getBytes(StandardCharsets.UTF_8)));
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                        + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                Hashing.sha512("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void providerRequiresSha512() {
        assertEquals(HashAlgorithm.SHA512, new ModrinthReputationProvider(new FakeTransport(),
                () -> 0L).requiredAlgorithm());
    }

    @Test
    void usesSha512EndpointAndParses200() {
        FakeTransport t = new FakeTransport();
        t.next = new HttpTransport.Response(200,
                "{\"project_id\":\"AaBbCc\",\"version_number\":\"1.2.3\"}", Map.of());
        ReputationResult r = provider(t, new AtomicLong(0)).lookup(SHA512);

        assertEquals(ReputationStatus.KNOWN_ON_PLATFORM, r.status());
        assertEquals("AaBbCc", r.projectName());
        assertEquals("1.2.3", r.versionName());
        // Must hit the sha512 endpoint with the correct algorithm parameter.
        assertEquals("https://api.modrinth.com/v2/version_file/" + SHA512 + "?algorithm=sha512",
                t.lastUri.get().toString());
    }

    @Test
    void notFoundIsUnknown() {
        FakeTransport t = new FakeTransport();
        t.next = new HttpTransport.Response(404, "", Map.of());
        assertEquals(ReputationStatus.UNKNOWN, provider(t, new AtomicLong(0)).lookup(SHA512).status());
    }

    @Test
    void malformedJsonIsUnavailable() {
        FakeTransport t = new FakeTransport();
        t.next = new HttpTransport.Response(200, "this is not json", Map.of());
        assertEquals(ReputationStatus.LOOKUP_UNAVAILABLE, provider(t, new AtomicLong(0)).lookup(SHA512).status());
    }

    @Test
    void networkFailureIsUnavailable() {
        FakeTransport t = new FakeTransport();
        t.toThrow = new IOException("offline");
        assertEquals(ReputationStatus.LOOKUP_UNAVAILABLE, provider(t, new AtomicLong(0)).lookup(SHA512).status());
    }

    @Test
    void rateLimitBacksOffWithoutMoreRequests() {
        FakeTransport t = new FakeTransport();
        t.next = new HttpTransport.Response(429, "", Map.of("Retry-After", List.of("30")));
        AtomicLong clock = new AtomicLong(1000);
        ModrinthReputationProvider p = provider(t, clock);

        assertEquals(ReputationStatus.LOOKUP_UNAVAILABLE, p.lookup(SHA512).status());
        assertEquals(1, t.calls.get());
        // Still within the 30s cool-down: must NOT call the transport again.
        clock.set(1000 + 10_000);
        assertEquals(ReputationStatus.LOOKUP_UNAVAILABLE, p.lookup(SHA512).status());
        assertEquals(1, t.calls.get(), "must not hit the API during backoff");
    }

    @Test
    void cachesDefinitiveAnswers() {
        FakeTransport t = new FakeTransport();
        t.next = new HttpTransport.Response(200,
                "{\"project_id\":\"P\",\"version_number\":\"1\"}", Map.of());
        ModrinthReputationProvider p = provider(t, new AtomicLong(0));
        p.lookup(SHA512);
        p.lookup(SHA512);
        assertEquals(1, t.calls.get(), "second identical lookup should be served from cache");
    }

    @Test
    void invalidHashIsRejectedWithoutRequest() {
        FakeTransport t = new FakeTransport();
        ReputationResult r = provider(t, new AtomicLong(0)).lookup("not-a-valid-sha512");
        assertEquals(ReputationStatus.LOOKUP_UNAVAILABLE, r.status());
        assertEquals(0, t.calls.get(), "a malformed hash must never trigger a network request");
    }
}
