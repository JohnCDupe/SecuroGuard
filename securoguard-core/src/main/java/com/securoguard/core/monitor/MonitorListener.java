package com.securoguard.core.monitor;

import java.nio.file.Path;
import java.util.Set;

/**
 * Callbacks from {@link FilesystemMonitor}. Implementations must be thread-safe:
 * calls may arrive on the watch thread or a scan-executor thread. Implementations
 * must not perform slow work on {@link #onFileSettled}'s caller if that caller is
 * the render thread — the monitor already dispatches scanning off the watch thread,
 * but adapters (the Fabric mod) are responsible for their own thread affinity.
 */
public interface MonitorListener {

    /** A newly created or modified file has stopped changing and is safe to scan. */
    void onFileSettled(Path file);

    /** A watched file was removed. */
    void onFileRemoved(Path file);

    /**
     * A full reconciliation completed (after OVERFLOW or on the periodic timer).
     * {@code currentFiles} is the complete current set of regular files in the
     * watched directory, letting the listener recover any events it missed.
     */
    void onReconciled(Set<Path> currentFiles);

    /**
     * The monitor hit a problem. The monitor reports rather than dying silently;
     * whether it can continue is indicated by {@code fatal}.
     */
    void onFailure(String message, Throwable cause, boolean fatal);
}
