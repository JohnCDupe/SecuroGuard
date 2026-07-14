package com.securoguard.core.reputation;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal HTTP GET abstraction so the reputation client can be tested without any
 * real network. Production uses {@link JdkHttpTransport}; tests supply a fake that
 * returns canned responses and records the requested URIs.
 */
public interface HttpTransport {

    Response get(URI uri, Map<String, String> headers, Duration timeout) throws IOException, InterruptedException;

    /** An immutable view of an HTTP response, enough for the reputation client. */
    record Response(int statusCode, String body, Map<String, List<String>> headers) {

        /** Reads a header as a long (e.g. {@code Retry-After}), if present and numeric. */
        public Optional<Long> firstHeaderLong(String name) {
            if (headers == null) {
                return Optional.empty();
            }
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() != null && e.getKey().equalsIgnoreCase(name)
                        && e.getValue() != null && !e.getValue().isEmpty()) {
                    try {
                        return Optional.of(Long.parseLong(e.getValue().get(0).trim()));
                    } catch (NumberFormatException ignored) {
                        return Optional.empty();
                    }
                }
            }
            return Optional.empty();
        }
    }
}
