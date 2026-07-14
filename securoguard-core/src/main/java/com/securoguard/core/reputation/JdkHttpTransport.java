package com.securoguard.core.reputation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

/**
 * Production {@link HttpTransport} backed by the JDK {@link HttpClient}. Hash-only
 * GETs, short connect timeout, redirects followed normally. No content is ever
 * uploaded — this only issues GET requests with header metadata.
 */
public final class JdkHttpTransport implements HttpTransport {

    private final HttpClient http;

    public JdkHttpTransport() {
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    @Override
    public Response get(URI uri, Map<String, String> headers, Duration timeout)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(uri).timeout(timeout).GET();
        headers.forEach(builder::header);
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        return new Response(response.statusCode(), response.body(), response.headers().map());
    }
}
