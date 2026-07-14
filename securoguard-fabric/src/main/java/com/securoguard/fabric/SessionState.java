package com.securoguard.fabric;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Tracks whether a play session is active and, if so, whether it is a multiplayer
 * connection or a single-player integrated server.
 *
 * <p>Privacy by construction: the raw server address is never stored or
 * transmitted. We keep only a boolean "connected to multiplayer" and coarse
 * timing. This is enough to attribute an event as "occurred while connected"
 * without ever implying the server was responsible or leaking where the player is.
 */
public final class SessionState {

    public enum Kind {DISCONNECTED, SINGLEPLAYER, MULTIPLAYER}

    private final AtomicReference<Kind> kind = new AtomicReference<>(Kind.DISCONNECTED);
    private volatile Instant sessionStart;
    private volatile Instant sessionEnd;

    public void onJoin(boolean integratedServer) {
        kind.set(integratedServer ? Kind.SINGLEPLAYER : Kind.MULTIPLAYER);
        sessionStart = Instant.now();
        sessionEnd = null;
    }

    public void onDisconnect() {
        kind.set(Kind.DISCONNECTED);
        sessionEnd = Instant.now();
    }

    public Kind kind() {
        return kind.get();
    }

    /** A session is "active" for rule purposes whenever we are in a world at all. */
    public boolean isSessionActive() {
        return kind.get() != Kind.DISCONNECTED;
    }

    /** True only for multiplayer; single-player integrated sessions are treated separately. */
    public boolean isConnectedToServer() {
        return kind.get() == Kind.MULTIPLAYER;
    }

    public Instant sessionStart() {
        return sessionStart;
    }

    public Instant sessionEnd() {
        return sessionEnd;
    }
}
