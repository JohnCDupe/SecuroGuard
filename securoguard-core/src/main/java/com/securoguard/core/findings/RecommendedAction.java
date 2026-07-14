package com.securoguard.core.findings;

/**
 * Machine-readable recommendation attached to a finding. The UI/CLI maps these to
 * concrete controls (buttons, exit codes); rules stay free of presentation logic.
 */
public enum RecommendedAction {
    /** Nothing to do; purely informational. */
    NONE,
    /** Keep watching; no action required yet. */
    MONITOR,
    /** A human should look at this file/mod. */
    REVIEW,
    /** Strongly consider quarantining the file (never automatic). */
    QUARANTINE,
    /** Consider leaving the current server and reviewing before reconnecting. */
    DISCONNECT_AND_REVIEW,
    /** Update the affected mod to a fixed version. */
    UPDATE
}
