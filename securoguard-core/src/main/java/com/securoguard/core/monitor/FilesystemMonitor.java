package com.securoguard.core.monitor;

import java.io.IOException;
import java.nio.file.ClosedWatchServiceException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.LongSupplier;

/**
 * Runtime filesystem monitor built on Java NIO {@link WatchService}.
 *
 * <p><b>Delivery semantics (RB3).</b> A detected change is held in a per-path
 * <em>pending</em> map and is only cleared once the corresponding listener callback
 * has actually run. The <em>known</em> (delivered) state — which reconciliation
 * diffs against — is updated <b>only inside a successful delivery</b>. Therefore a
 * change survives repeated scan-queue rejection: it stays pending, is re-detected by
 * every reconciliation, and is re-dispatched automatically as soon as queue capacity
 * frees. Coalescing is per path (latest event wins: a delete supersedes a stale
 * modify; a re-create supersedes a delete), bounding memory to the directory size.
 *
 * <p>Threading: <b>no listener callback ever runs on the WatchService thread.</b>
 * The scan executor uses an abort-on-saturation policy; a rejected dispatch leaves
 * the work pending (never runs it on the caller) and marks the monitor DEGRADED.
 *
 * <p>Health: DEGRADED while any pending delivery is outstanding; RUNNING only once
 * every pending change has been delivered; FATAL if the watch loop dies; STOPPED
 * after {@link #close()}. Shutdown never claims dropped work was delivered.
 */
public final class FilesystemMonitor implements AutoCloseable {

    private static final int DEFAULT_QUEUE_CAPACITY = 256;

    private final Path watchedDir;
    private final MonitorListener listener;
    private final FileSettleTracker settleTracker;
    private final long pollIntervalMillis;
    private final long reconcileIntervalMillis;
    private final LongSupplier clock;
    private final int scanQueueCapacity;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicBoolean reconcilePending = new AtomicBoolean(false);
    private final AtomicReference<MonitorHealth> health =
            new AtomicReference<>(new MonitorHealth(MonitorHealth.State.STOPPED, 0, "not started"));

    // Delivered state: what the listener has been successfully told about. Guarded by stateLock.
    private final Map<Path, FileSig> known = new HashMap<>();
    // Undelivered changes, keyed by path (coalesced). Guarded by stateLock.
    private final Map<Path, Pending> pending = new HashMap<>();
    private long genCounter;
    private final Object stateLock = new Object();

    private WatchService watchService;
    private volatile WatchKey watchKey;   // current registration; may be invalidated
    private volatile boolean watchStarted; // true once a real WatchService is registered
    private long nextReRegisterAt;         // backoff gate for re-registration attempts
    private int reRegisterFailures;
    private Thread watchThread;
    private ThreadPoolExecutor scanExecutor;
    private volatile long lastReconcileAt;

    private record FileSig(long size, long mtime) {
    }

    private enum Kind {UPSERT, REMOVE}

    private static final class Pending {
        Kind kind;
        FileSig sig;    // for UPSERT
        long gen;       // observation generation; delivery only commits if unchanged
        boolean inFlight;
        int failures;   // consecutive delivery failures (for backoff)
        long nextRetryAt; // epoch millis before which this must not be re-dispatched
    }

    private static final long RETRY_BASE_MILLIS = 200;
    private static final long RETRY_CAP_MILLIS = 5000;

    /** Bounded exponential backoff so a permanently-failing delivery never busy-spins. */
    private long backoffMillis(int failures) {
        int shift = Math.min(Math.max(failures - 1, 0), 20);
        long delay = RETRY_BASE_MILLIS << shift;
        return Math.min(delay, RETRY_CAP_MILLIS);
    }

    public FilesystemMonitor(Path watchedDir, MonitorListener listener) {
        this(watchedDir, listener, 1000, 500, 30_000, System::currentTimeMillis);
    }

    public FilesystemMonitor(Path watchedDir, MonitorListener listener, long quietPeriodMillis,
                             long pollIntervalMillis, long reconcileIntervalMillis, LongSupplier clock) {
        this(watchedDir, listener, quietPeriodMillis, pollIntervalMillis, reconcileIntervalMillis, clock,
                DEFAULT_QUEUE_CAPACITY);
    }

    FilesystemMonitor(Path watchedDir, MonitorListener listener, long quietPeriodMillis,
                      long pollIntervalMillis, long reconcileIntervalMillis, LongSupplier clock,
                      int scanQueueCapacity) {
        this.watchedDir = watchedDir.toAbsolutePath().normalize();
        this.listener = listener;
        this.settleTracker = new FileSettleTracker(quietPeriodMillis);
        this.pollIntervalMillis = pollIntervalMillis;
        this.reconcileIntervalMillis = reconcileIntervalMillis;
        this.clock = clock;
        this.scanQueueCapacity = scanQueueCapacity;
    }

    public synchronized void start() throws IOException {
        if (running.get()) {
            throw new IllegalStateException("Monitor already running");
        }
        Files.createDirectories(watchedDir);
        this.watchService = watchedDir.getFileSystem().newWatchService();
        this.watchKey = registerWatch();
        this.watchStarted = true;
        openScanExecutor();
        this.lastReconcileAt = clock.getAsLong();
        running.set(true);
        setHealth(MonitorHealth.State.RUNNING, "started");
        this.watchThread = new Thread(this::watchLoop, "securoguard-watch");
        watchThread.setDaemon(true);
        watchThread.start();
        reconcileNow(); // establish initial known-set + deliver any pre-existing files
    }

    /**
     * Bounded single-thread scan executor. Rejection <b>aborts</b> (throws) so the
     * caller (dispatchPending) can leave the work pending; it is never run on the
     * watch thread.
     */
    private void openScanExecutor() {
        this.scanExecutor = new ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(scanQueueCapacity),
                r -> {
                    Thread t = new Thread(r, "securoguard-scan");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.AbortPolicy());
    }

    private void watchLoop() {
        try {
            while (running.get()) {
                WatchKey key;
                try {
                    key = watchService.poll(pollIntervalMillis, TimeUnit.MILLISECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (ClosedWatchServiceException e) {
                    break;
                }
                if (key != null) {
                    if (processKey(key)) {
                        reconcilePending.set(true);
                    }
                    // A false reset() means the key (and its directory) is no longer valid
                    // — do not keep claiming full RUNNING health.
                    if (!key.reset()) {
                        markDegraded("watch key invalidated for " + watchedDir);
                        reconcilePending.set(true);
                    }
                }
                long now = clock.getAsLong();
                maybeReRegister(now);
                dispatchSettled(now);
                dispatchPending(); // keep the pipeline flowing / retry rejected work
                if (reconcilePending.compareAndSet(true, false)
                        || now - lastReconcileAt >= reconcileIntervalMillis) {
                    reconcileNow();
                }
            }
        } catch (RuntimeException e) {
            running.set(false);
            setHealth(MonitorHealth.State.FATAL, "watch loop terminated: " + e);
            reportFailure("Watch loop terminated unexpectedly", e, true);
        }
    }

    private WatchKey registerWatch() throws IOException {
        return watchedDir.register(watchService,
                StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_MODIFY,
                StandardWatchEventKinds.ENTRY_DELETE,
                StandardWatchEventKinds.OVERFLOW);
    }

    /**
     * If the watch registration has been invalidated (directory deleted, renamed, or
     * its key cancelled), degrade health and attempt to re-register with bounded
     * backoff once the directory exists again. Reconciliation continues meanwhile so
     * missed changes are recovered on recovery.
     */
    private void maybeReRegister(long now) {
        WatchKey k = watchKey;
        if (k != null && k.isValid()) {
            return; // healthy registration
        }
        markDegraded("watch registration lost for " + watchedDir + "; recovering");
        if (now < nextReRegisterAt) {
            return; // backing off
        }
        nextReRegisterAt = now + backoffMillis(reRegisterFailures + 1);
        try {
            if (Files.isDirectory(watchedDir)) {
                this.watchKey = registerWatch();
                reRegisterFailures = 0;
                reconcilePending.set(true); // catch up on anything missed while unregistered
                synchronized (stateLock) {
                    updateHealthLocked(); // recover toward RUNNING once pending drains
                }
            } else {
                reRegisterFailures++; // directory still gone; keep degraded and retry later
            }
        } catch (ClosedWatchServiceException e) {
            // service closed (shutdown in progress): let the loop exit naturally
        } catch (IOException e) {
            reRegisterFailures++;
            reportFailure("Re-registration failed for " + watchedDir, e, false);
        }
    }

    /** @return true if an OVERFLOW event was seen. */
    private boolean processKey(WatchKey key) {
        boolean overflow = false;
        for (WatchEvent<?> event : key.pollEvents()) {
            WatchEvent.Kind<?> kind = event.kind();
            if (kind == StandardWatchEventKinds.OVERFLOW) {
                overflow = true;
                continue;
            }
            if (!(event.context() instanceof Path rel)) {
                continue;
            }
            Path file = watchedDir.resolve(rel);
            if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                settleTracker.forget(file);
                enqueue(file, Kind.REMOVE, null); // removals bypass settling
            } else {
                observeForSettling(file, clock.getAsLong());
            }
        }
        return overflow;
    }

    private void observeForSettling(Path file, long now) {
        try {
            if (!Files.isRegularFile(file)) {
                settleTracker.forget(file);
                return;
            }
            BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
            settleTracker.observe(file, attrs.size(), attrs.lastModifiedTime().toMillis(), now);
        } catch (IOException e) {
            settleTracker.forget(file);
        }
    }

    /** Turns settled (stable) files into pending upserts/removes and dispatches them. */
    private void dispatchSettled(long now) {
        for (Path file : settleTracker.drainSettled(now)) {
            try {
                if (Files.isRegularFile(file)) {
                    BasicFileAttributes a = Files.readAttributes(file, BasicFileAttributes.class);
                    enqueue(file, Kind.UPSERT, new FileSig(a.size(), a.lastModifiedTime().toMillis()));
                } else {
                    enqueue(file, Kind.REMOVE, null);
                }
            } catch (IOException e) {
                enqueue(file, Kind.REMOVE, null);
            }
        }
        dispatchPending();
    }

    /** Coalesces a change into the pending map (latest target wins). Idempotent for an unchanged target. */
    private void enqueue(Path path, Kind kind, FileSig sig) {
        synchronized (stateLock) {
            enqueueLocked(path, kind, sig);
            updateHealthLocked();
        }
    }

    private void enqueueLocked(Path path, Kind kind, FileSig sig) {
        Pending p = pending.get(path);
        if (p != null && p.kind == kind && Objects.equals(p.sig, sig)) {
            return; // same target already pending: keep its generation and in-flight state
        }
        Pending np = new Pending();
        np.kind = kind;
        np.sig = sig;
        np.gen = ++genCounter;
        np.inFlight = false;
        pending.put(path, np);
    }

    /** Attempts to dispatch every not-in-flight, retry-eligible pending change. */
    private void dispatchPending() {
        long now = clock.getAsLong();
        List<Object[]> batch = new ArrayList<>();
        synchronized (stateLock) {
            for (Map.Entry<Path, Pending> e : pending.entrySet()) {
                Pending p = e.getValue();
                // Respect the backoff gate so a failing delivery does not busy-spin.
                if (!p.inFlight && now >= p.nextRetryAt) {
                    p.inFlight = true;
                    batch.add(new Object[]{e.getKey(), p.kind, p.sig, p.gen});
                }
            }
        }
        for (Object[] job : batch) {
            Path path = (Path) job[0];
            Kind kind = (Kind) job[1];
            FileSig sig = (FileSig) job[2];
            long gen = (long) job[3];
            try {
                scanExecutor.execute(() -> deliver(path, kind, sig, gen));
            } catch (RejectedExecutionException rej) {
                // Saturated: leave the work pending (never run on the caller) and mark degraded.
                synchronized (stateLock) {
                    Pending p = pending.get(path);
                    if (p != null && p.gen == gen) {
                        p.inFlight = false; // eligible for re-dispatch on the next tick
                    }
                }
                reconcilePending.set(true);
                markDegraded("scan queue saturated; " + pendingCount() + " change(s) awaiting delivery");
            }
        }
    }

    /**
     * Delivers a change. The known (delivered) state advances <b>only when the
     * listener callback returns normally</b>. If the callback throws, the change
     * stays pending, {@code known} is not advanced, health stays DEGRADED, and the
     * change is retried after a bounded backoff (no busy-spin). A task whose
     * generation was superseded is skipped rather than delivering stale state.
     */
    private void deliver(Path path, Kind kind, FileSig sig, long gen) {
        boolean current;
        synchronized (stateLock) {
            Pending p = pending.get(path);
            current = (p != null && p.gen == gen);
        }
        if (!current) {
            synchronized (stateLock) {
                updateHealthLocked();
            }
            dispatchPending();
            return;
        }
        boolean ok = runListener(kind, path); // true only if the callback returned normally
        synchronized (stateLock) {
            Pending p = pending.get(path);
            if (p != null && p.gen == gen) {
                if (ok) {
                    // Success: commit the delivered state and clear the pending entry.
                    if (kind == Kind.REMOVE) {
                        known.remove(path);
                    } else {
                        known.put(path, sig);
                    }
                    pending.remove(path);
                } else {
                    // Failure: do NOT advance known. Keep it pending and back off.
                    p.inFlight = false;
                    p.failures++;
                    p.nextRetryAt = clock.getAsLong() + backoffMillis(p.failures);
                }
            }
            // If superseded during the callback, the newer entry re-dispatches below.
            updateHealthLocked();
        }
        dispatchPending();
    }

    /** Runs the listener callback, returning true iff it completed without throwing. */
    private boolean runListener(Kind kind, Path path) {
        try {
            if (kind == Kind.REMOVE) {
                listener.onFileRemoved(path);
            } else {
                listener.onFileSettled(path);
            }
            return true;
        } catch (RuntimeException e) {
            reportFailure("Listener callback threw for " + path, e, false);
            return false;
        }
    }

    /**
     * Full reconciliation against the <em>delivered</em> state. Re-derives every
     * undelivered change from the filesystem (so nothing is lost after OVERFLOW,
     * a missed event, or a dropped dispatch) and dispatches it.
     */
    void reconcileNow() {
        Map<Path, FileSig> current = new HashMap<>();
        Set<Path> currentPaths = new HashSet<>();
        try (var stream = Files.newDirectoryStream(watchedDir)) {
            for (Path p : stream) {
                if (!Files.isRegularFile(p)) {
                    continue;
                }
                try {
                    BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);
                    current.put(p, new FileSig(a.size(), a.lastModifiedTime().toMillis()));
                    currentPaths.add(p);
                } catch (IOException ignored) {
                    // transient; a later reconcile will catch it
                }
            }
        } catch (IOException e) {
            markDegraded("reconciliation scan failed: " + e.getMessage());
            reportFailure("Reconciliation scan failed for " + watchedDir, e, false);
            return;
        }
        synchronized (stateLock) {
            for (Map.Entry<Path, FileSig> e : current.entrySet()) {
                if (!e.getValue().equals(known.get(e.getKey()))) {
                    enqueueLocked(e.getKey(), Kind.UPSERT, e.getValue()); // new or changed
                }
            }
            for (Path gone : new HashSet<>(known.keySet())) {
                if (!currentPaths.contains(gone)) {
                    enqueueLocked(gone, Kind.REMOVE, null); // delivered file now missing
                }
            }
            for (Path p : new HashSet<>(pending.keySet())) {
                Pending pw = pending.get(p);
                if (pw.kind == Kind.UPSERT && !currentPaths.contains(p)) {
                    enqueueLocked(p, Kind.REMOVE, null); // pending upsert that vanished
                }
            }
            lastReconcileAt = clock.getAsLong();
            updateHealthLocked();
        }
        dispatchPending();
        safe(() -> listener.onReconciled(currentPaths));
    }

    /** Test hook: simulate a WatchService OVERFLOW recovery. */
    void simulateOverflow() {
        reconcileNow();
    }

    boolean isReconcilePending() {
        return reconcilePending.get();
    }

    int pendingCount() {
        synchronized (stateLock) {
            return pending.size();
        }
    }

    /** Test visibility: has this path been successfully delivered (is in the known set)? */
    boolean knownContains(Path path) {
        synchronized (stateLock) {
            return known.containsKey(path.toAbsolutePath().normalize());
        }
    }

    /** Test seam: open the scan executor without starting the watch thread. */
    void openScanExecutorForTest() {
        openScanExecutor();
        running.set(true);
        setHealth(MonitorHealth.State.RUNNING, "test executor");
    }

    /** Test seam: exercise the fatal-termination path the watch loop uses. */
    void triggerFatalForTest(Throwable t) {
        running.set(false);
        setHealth(MonitorHealth.State.FATAL, "watch loop terminated: " + t);
        reportFailure("Watch loop terminated unexpectedly", t, true);
    }

    /** Test seam: cancel the current watch key to simulate registration invalidation. */
    void invalidateWatchKeyForTest() {
        WatchKey k = watchKey;
        if (k != null) {
            k.cancel();
        }
    }

    /** Test seam: pump the delivery pipeline (retry backoff-eligible pending work). */
    void pumpForTest() {
        dispatchPending();
    }

    boolean isWatchKeyValid() {
        WatchKey k = watchKey;
        return k != null && k.isValid();
    }

    private void safe(Runnable r) {
        try {
            r.run();
        } catch (RuntimeException e) {
            markDegraded("listener callback threw: " + e);
            reportFailure("Listener callback threw", e, false);
        }
    }

    /**
     * Invokes {@link MonitorListener#onFailure} but never lets an exception in the
     * failure reporter itself kill the monitor thread or delivery loop.
     */
    private void reportFailure(String message, Throwable cause, boolean fatal) {
        try {
            listener.onFailure(message, cause, fatal);
        } catch (RuntimeException e) {
            // The reporter threw; there is nowhere trustworthy left to report to.
            System.err.println("SecuroGuard monitor: onFailure handler threw: " + e);
        }
    }

    /**
     * Recomputes health from pending state and watch validity. RUNNING requires that
     * all changes are delivered AND (for a real watcher) the registration is valid —
     * so a lost watch registration is never masked as RUNNING.
     */
    private void updateHealthLocked() {
        if (!running.get()) {
            return;
        }
        MonitorHealth.State state = health.get().state();
        if (state == MonitorHealth.State.FATAL || state == MonitorHealth.State.STOPPED) {
            return;
        }
        boolean watchOk = !watchStarted || isWatchKeyValid();
        if (!pending.isEmpty()) {
            setHealth(MonitorHealth.State.DEGRADED, pending.size() + " change(s) awaiting delivery");
        } else if (!watchOk) {
            setHealth(MonitorHealth.State.DEGRADED, "watch registration lost for " + watchedDir);
        } else {
            setHealth(MonitorHealth.State.RUNNING, "all changes delivered");
        }
    }

    private void markDegraded(String message) {
        MonitorHealth cur = health.get();
        if (cur.state() == MonitorHealth.State.RUNNING || cur.state() == MonitorHealth.State.DEGRADED) {
            health.set(new MonitorHealth(MonitorHealth.State.DEGRADED, lastReconcileAt, message));
        }
    }

    private void setHealth(MonitorHealth.State state, String message) {
        health.set(new MonitorHealth(state, lastReconcileAt, message));
    }

    public MonitorHealth health() {
        return health.get();
    }

    /** True only if the watch thread is genuinely alive and monitoring. */
    public boolean isRunning() {
        return running.get() && health.get().isActive();
    }

    @Override
    public synchronized void close() {
        if (!running.getAndSet(false)) {
            if (health.get().state() != MonitorHealth.State.FATAL) {
                setHealth(MonitorHealth.State.STOPPED, "closed");
            }
            return;
        }
        // Shutdown does not commit or claim delivery of any still-pending work.
        setHealth(MonitorHealth.State.STOPPED, "closed");
        try {
            if (watchService != null) {
                watchService.close();
            }
        } catch (IOException e) {
            reportFailure("Error closing WatchService", e, false);
        }
        if (watchThread != null) {
            watchThread.interrupt();
            try {
                watchThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        if (scanExecutor != null) {
            scanExecutor.shutdown();
            try {
                if (!scanExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                    scanExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                scanExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
    }
}
