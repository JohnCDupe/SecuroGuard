package com.securoguard.fabric;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Deterministic coverage of session/connection tracking (no Minecraft classes).
 * Single-player integrated sessions must be treated separately from multiplayer,
 * and no server address is ever retained.
 */
class SessionStateTest {

    @Test
    void multiplayerJoinIsConnectedToServer() {
        SessionState s = new SessionState();
        s.onJoin(false); // integratedServer = false => multiplayer
        assertTrue(s.isSessionActive());
        assertTrue(s.isConnectedToServer());
        assertEquals(SessionState.Kind.MULTIPLAYER, s.kind());
        assertNotNull(s.sessionStart());
    }

    @Test
    void singlePlayerIsActiveButNotConnectedToServer() {
        SessionState s = new SessionState();
        s.onJoin(true); // integrated server
        assertTrue(s.isSessionActive());
        assertFalse(s.isConnectedToServer(), "single-player is tracked separately from multiplayer");
        assertEquals(SessionState.Kind.SINGLEPLAYER, s.kind());
    }

    @Test
    void disconnectClearsSession() {
        SessionState s = new SessionState();
        s.onJoin(false);
        s.onDisconnect();
        assertFalse(s.isSessionActive());
        assertFalse(s.isConnectedToServer());
        assertEquals(SessionState.Kind.DISCONNECTED, s.kind());
        assertNotNull(s.sessionEnd());
    }
}
