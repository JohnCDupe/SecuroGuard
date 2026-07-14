package com.securoguard.core.monitor;

/**
 * A snapshot of the monitor's health, so a UI or CLI can tell the difference
 * between "monitoring normally", "still running but degraded", and "the watcher
 * died". SecuroGuard must never claim monitoring is active after the watch thread
 * has terminated.
 *
 * @param state                          current state
 * @param lastSuccessfulReconcileMillis  epoch millis of the last successful
 *                                       reconciliation, or 0 if none yet
 * @param message                        human-readable detail (e.g. why degraded)
 */
public record MonitorHealth(State state, long lastSuccessfulReconcileMillis, String message) {

    public enum State {
        /** Watch thread alive, events flowing, reconciliations succeeding. */
        RUNNING,
        /** Still running, but something was dropped/failed (e.g. scan queue saturated). */
        DEGRADED,
        /** Cleanly stopped via close(). */
        STOPPED,
        /** The watch loop terminated unexpectedly; monitoring is NOT active. */
        FATAL
    }

    public boolean isActive() {
        return state == State.RUNNING || state == State.DEGRADED;
    }
}
