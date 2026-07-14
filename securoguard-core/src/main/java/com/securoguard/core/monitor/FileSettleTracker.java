package com.securoguard.core.monitor;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Debounces filesystem events and decides when a file has "settled" — i.e. its
 * size and last-modified time have not changed for a configured quiet period.
 *
 * <p>This exists because a JAR being written (or copied) into {@code mods/}
 * produces a burst of {@code ENTRY_CREATE}/{@code ENTRY_MODIFY} events while the
 * bytes are still arriving. Hashing a half-written file wastes work and produces
 * a wrong hash. We wait until the file stops changing before scanning it.
 *
 * <p>Pure logic with an injected time source, so debounce/settling behaviour is
 * unit-testable without real clocks or files.
 */
public final class FileSettleTracker {

    private final long quietPeriodMillis;
    private final Map<Path, Pending> pending = new HashMap<>();

    public FileSettleTracker(long quietPeriodMillis) {
        this.quietPeriodMillis = quietPeriodMillis;
    }

    private static final class Pending {
        long size;
        long mtime;
        long lastChangedAt;
    }

    /**
     * Records an observation of a file. If the size or mtime changed since the last
     * observation (or the file is new to us) the settle timer resets to {@code now}.
     */
    public synchronized void observe(Path file, long size, long mtime, long now) {
        Pending p = pending.get(file);
        if (p == null) {
            p = new Pending();
            p.size = size;
            p.mtime = mtime;
            p.lastChangedAt = now;
            pending.put(file, p);
            return;
        }
        if (p.size != size || p.mtime != mtime) {
            p.size = size;
            p.mtime = mtime;
            p.lastChangedAt = now; // still changing: restart the quiet period
        }
    }

    /** Forgets a file (e.g. it was deleted before it ever settled). */
    public synchronized void forget(Path file) {
        pending.remove(file);
    }

    /**
     * Removes and returns every file that has been unchanged for at least the quiet
     * period as of {@code now}. Callers then scan these files off the watch thread.
     */
    public synchronized List<Path> drainSettled(long now) {
        List<Path> settled = new ArrayList<>();
        var it = pending.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<Path, Pending> e = it.next();
            if (now - e.getValue().lastChangedAt >= quietPeriodMillis) {
                settled.add(e.getKey());
                it.remove();
            }
        }
        return settled;
    }

    public synchronized int pendingCount() {
        return pending.size();
    }
}
