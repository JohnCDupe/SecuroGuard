package com.securoguard.core.monitor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RB3/R7: monitor delivery guarantees. Every detected change survives sustained
 * scan-queue saturation and is eventually delivered once capacity frees; the known
 * (delivered) state is only advanced on successful delivery; health stays DEGRADED
 * while work is undelivered; no callback runs on the watch thread.
 */
class MonitorThreadingTest {

    /** A listener whose "blocker" delivery blocks the single worker until released. */
    static final class BlockingListener implements MonitorListener {
        final CountDownLatch release = new CountDownLatch(1);
        final CountDownLatch blockerStarted = new CountDownLatch(1);
        final CopyOnWriteArrayList<String> delivered = new CopyOnWriteArrayList<>();
        final ConcurrentHashMap<String, AtomicInteger> deliveredCount = new ConcurrentHashMap<>();
        final CopyOnWriteArrayList<String> removed = new CopyOnWriteArrayList<>();
        final CopyOnWriteArrayList<String> failures = new CopyOnWriteArrayList<>();

        @Override public void onFileSettled(Path file) {
            String name = file.getFileName().toString();
            if (name.startsWith("blocker")) {
                blockerStarted.countDown();
                try {
                    release.await(5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            } else {
                delivered.add(name);
                deliveredCount.computeIfAbsent(name, k -> new AtomicInteger()).incrementAndGet();
            }
        }
        @Override public void onFileRemoved(Path file) {
            removed.add(file.getFileName().toString());
        }
        @Override public void onReconciled(Set<Path> currentFiles) { }
        @Override public void onFailure(String message, Throwable cause, boolean fatal) {
            failures.add((fatal ? "FATAL:" : "warn:") + message);
        }
    }

    private FilesystemMonitor saturatedMonitor(Path dir, BlockingListener l) throws IOException {
        // Quiet period 0 so settling is immediate; queue capacity 1 so a blocked worker
        // saturates after one queued item. No watch thread — we drive reconcile directly.
        FilesystemMonitor m = new FilesystemMonitor(dir, l, 0, 100, 600_000, System::currentTimeMillis, 1);
        m.openScanExecutorForTest();
        Files.writeString(dir.resolve("blocker.dat"), "x");
        m.reconcileNow();                       // dispatch blocker -> worker picks it and blocks
        assertTrue(await(l.blockerStarted, 3000), "worker should be occupied by the blocker");
        return m;
    }

    private static boolean await(CountDownLatch l, long ms) {
        try {
            return l.await(ms, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    private void awaitTrue(java.util.function.BooleanSupplier cond, long ms) {
        long deadline = System.currentTimeMillis() + ms;
        while (!cond.getAsBoolean() && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(20);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        assertTrue(cond.getAsBoolean(), "condition not met within " + ms + "ms");
    }

    @Test
    void additionSurvivesSustainedSaturationAndIsDelivered(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        try (FilesystemMonitor m = saturatedMonitor(dir, l)) {
            Files.writeString(dir.resolve("A.jar"), "a");
            Files.writeString(dir.resolve("B.jar"), "b");
            m.reconcileNow();  // A queued, B rejected (queue full)
            m.reconcileNow();  // sustained saturation: B must remain pending, not be lost

            assertEquals(MonitorHealth.State.DEGRADED, m.health().state());
            assertFalse(m.knownContains(dir.resolve("A.jar")), "not delivered while saturated");
            assertFalse(m.knownContains(dir.resolve("B.jar")));
            assertTrue(m.pendingCount() >= 3, "blocker + A + B are pending");

            l.release.countDown(); // free the worker
            awaitTrue(() -> l.delivered.contains("A.jar") && l.delivered.contains("B.jar"), 6000);
            awaitTrue(() -> m.knownContains(dir.resolve("A.jar")) && m.knownContains(dir.resolve("B.jar")), 3000);
            awaitTrue(() -> m.pendingCount() == 0, 3000);
            assertEquals(MonitorHealth.State.RUNNING, m.health().state(),
                    "health returns to RUNNING only after all pending work is delivered");
        }
    }

    @Test
    void removalSurvivesSaturationAndIsDelivered(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        Path a = dir.resolve("A.jar");
        Files.writeString(a, "a");
        FilesystemMonitor m = new FilesystemMonitor(dir, l, 0, 100, 600_000, System::currentTimeMillis, 1);
        m.openScanExecutorForTest();
        m.reconcileNow(); // deliver A (no blocking yet) -> known A
        awaitTrue(() -> m.knownContains(a), 3000);

        // Now occupy the worker and delete A under saturation.
        Files.writeString(dir.resolve("blocker.dat"), "x");
        m.reconcileNow();
        assertTrue(await(l.blockerStarted, 3000));
        Files.delete(a);
        m.reconcileNow(); // enqueue REMOVE A (queued/rejected under saturation)
        m.reconcileNow();

        l.release.countDown();
        awaitTrue(() -> l.removed.contains("A.jar"), 6000);
        awaitTrue(() -> !m.knownContains(a), 3000);
        m.close();
    }

    @Test
    void removeThenRecreateResolvesToFinalState(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        Path a = dir.resolve("A.jar");
        try (FilesystemMonitor m = saturatedMonitor(dir, l)) {
            Files.writeString(a, "one");
            m.reconcileNow();     // pending UPSERT A
            Files.delete(a);
            m.reconcileNow();     // pending REMOVE A (supersedes)
            Files.writeString(a, "two-different");
            m.reconcileNow();     // pending UPSERT A again (final state present)

            l.release.countDown();
            awaitTrue(() -> l.delivered.contains("A.jar"), 6000);
            awaitTrue(() -> m.knownContains(a), 3000);   // final state: present
            assertTrue(Files.exists(a));
        }
    }

    @Test
    void repeatedModificationsCoalesceToOneDelivery(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        Path a = dir.resolve("A.jar");
        try (FilesystemMonitor m = saturatedMonitor(dir, l)) {
            Files.writeString(a, "v1");
            m.reconcileNow();
            Files.writeString(a, "v2-longer");
            m.reconcileNow();
            Files.writeString(a, "v3-longer-still");
            m.reconcileNow(); // three modifications, but coalesced to a single pending entry

            l.release.countDown();
            awaitTrue(() -> l.delivered.contains("A.jar"), 6000);
            awaitTrue(() -> m.pendingCount() == 0, 3000);
            assertEquals(1, l.deliveredCount.get("A.jar").get(),
                    "coalesced modifications deliver A exactly once");
        }
    }

    @Test
    void healthStaysDegradedUntilDeliveryRecovers(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        try (FilesystemMonitor m = saturatedMonitor(dir, l)) {
            Files.writeString(dir.resolve("A.jar"), "a");
            m.reconcileNow();
            assertEquals(MonitorHealth.State.DEGRADED, m.health().state(), "degraded while undelivered");
            l.release.countDown();
            awaitTrue(() -> m.health().state() == MonitorHealth.State.RUNNING, 6000);
        }
    }

    @Test
    void scanCallbacksNeverRunOnTheWatchThread(@TempDir Path dir) throws Exception {
        AtomicReference<String> callbackThread = new AtomicReference<>();
        MonitorListener listener = new MonitorListener() {
            @Override public void onFileSettled(Path file) {
                callbackThread.set(Thread.currentThread().getName());
            }
            @Override public void onFileRemoved(Path file) { }
            @Override public void onReconciled(Set<Path> currentFiles) { }
            @Override public void onFailure(String m, Throwable c, boolean f) { }
        };
        try (FilesystemMonitor monitor = new FilesystemMonitor(dir, listener, 150, 100, 5000,
                System::currentTimeMillis)) {
            monitor.start();
            Files.write(dir.resolve("x.jar"), new byte[]{1});
            awaitTrue(() -> callbackThread.get() != null, 10_000);
            assertNotEquals("securoguard-watch", callbackThread.get());
            assertTrue(callbackThread.get().startsWith("securoguard-scan"));
        }
    }

    @Test
    void listenerFailureIsReported(@TempDir Path dir) throws Exception {
        BlockingListener base = new BlockingListener();
        MonitorListener throwing = new MonitorListener() {
            @Override public void onFileSettled(Path file) {
                throw new RuntimeException("boom");
            }
            @Override public void onFileRemoved(Path file) { }
            @Override public void onReconciled(Set<Path> currentFiles) { }
            @Override public void onFailure(String message, Throwable cause, boolean fatal) {
                base.failures.add(message);
            }
        };
        FilesystemMonitor m = new FilesystemMonitor(dir, throwing, 0, 100, 600_000,
                System::currentTimeMillis, 4);
        m.openScanExecutorForTest();
        Files.writeString(dir.resolve("A.jar"), "a");
        m.reconcileNow();
        awaitTrue(() -> !base.failures.isEmpty(), 3000);
        m.close();
    }

    @Test
    void closeIsCleanAndReportsStopped(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        FilesystemMonitor monitor = new FilesystemMonitor(dir, l, 100, 100, 5000, System::currentTimeMillis);
        monitor.start();
        monitor.close();
        assertEquals(MonitorHealth.State.STOPPED, monitor.health().state());
        assertFalse(monitor.isRunning());
        assertTrue(l.failures.stream().noneMatch(s -> s.startsWith("FATAL")));
    }

    @Test
    void fatalTerminationIsVisibleAndStopsClaimingActive(@TempDir Path dir) {
        BlockingListener l = new BlockingListener();
        FilesystemMonitor monitor = new FilesystemMonitor(dir, l, 100, 100, 5000, System::currentTimeMillis);
        monitor.openScanExecutorForTest();
        monitor.triggerFatalForTest(new RuntimeException("watcher died"));
        assertEquals(MonitorHealth.State.FATAL, monitor.health().state());
        assertFalse(monitor.isRunning(), "a dead watcher must not report as monitoring");
        assertTrue(l.failures.stream().anyMatch(s -> s.startsWith("FATAL")));
        monitor.close();
    }

    // --- Phase 1B: truthful delivery on listener exception ---

    /** Listener that throws on the first N settle callbacks, then succeeds. */
    static final class ThrowingListener implements MonitorListener {
        final int throwTimes;
        final AtomicInteger attempts = new AtomicInteger();
        final CopyOnWriteArrayList<String> delivered = new CopyOnWriteArrayList<>();
        final CopyOnWriteArrayList<String> failures = new CopyOnWriteArrayList<>();
        final boolean failureReporterAlsoThrows;

        ThrowingListener(int throwTimes, boolean failureReporterAlsoThrows) {
            this.throwTimes = throwTimes;
            this.failureReporterAlsoThrows = failureReporterAlsoThrows;
        }

        @Override public void onFileSettled(Path file) {
            if (attempts.incrementAndGet() <= throwTimes) {
                throw new RuntimeException("boom");
            }
            delivered.add(file.getFileName().toString());
        }
        @Override public void onFileRemoved(Path file) { }
        @Override public void onReconciled(Set<Path> currentFiles) { }
        @Override public void onFailure(String message, Throwable cause, boolean fatal) {
            failures.add(message);
            if (failureReporterAlsoThrows) {
                throw new RuntimeException("onFailure also throws");
            }
        }
    }

    @Test
    void callbackThatThrowsOnceIsRetriedAndEventuallyDelivered(@TempDir Path dir) throws Exception {
        AtomicLong clock = new AtomicLong(1000);
        ThrowingListener l = new ThrowingListener(1, false);
        FilesystemMonitor m = new FilesystemMonitor(dir, l, 0, 100, 600_000, clock::get, 4);
        m.openScanExecutorForTest();
        Path a = dir.resolve("A.jar");
        Files.writeString(a, "a");

        m.reconcileNow(); // first delivery attempt throws
        awaitTrue(() -> l.attempts.get() >= 1 && !l.failures.isEmpty(), 3000);
        assertFalse(m.knownContains(a), "known must NOT advance after a failed callback");
        assertEquals(MonitorHealth.State.DEGRADED, m.health().state(), "health stays DEGRADED until success");

        // Advance the clock past the backoff, then pump: the retry should now succeed.
        clock.set(1000 + 1000);
        m.pumpForTest();
        awaitTrue(() -> l.delivered.contains("A.jar"), 3000);
        awaitTrue(() -> m.knownContains(a), 3000);
        awaitTrue(() -> m.health().state() == MonitorHealth.State.RUNNING, 3000);
        m.close();
    }

    @Test
    void permanentlyFailingCallbackDoesNotBusySpin(@TempDir Path dir) throws Exception {
        AtomicLong clock = new AtomicLong(1000); // frozen clock: backoff never elapses
        ThrowingListener l = new ThrowingListener(Integer.MAX_VALUE, false);
        FilesystemMonitor m = new FilesystemMonitor(dir, l, 0, 100, 600_000, clock::get, 4);
        m.openScanExecutorForTest();
        Files.writeString(dir.resolve("A.jar"), "a");

        m.reconcileNow();
        awaitTrue(() -> l.attempts.get() >= 1, 3000);
        // Pump many times with the clock frozen: backoff must prevent re-delivery.
        for (int i = 0; i < 50; i++) {
            m.pumpForTest();
        }
        Thread.sleep(100);
        assertEquals(1, l.attempts.get(), "backoff must prevent a busy-spin of retries");
        assertEquals(MonitorHealth.State.DEGRADED, m.health().state());
        m.close();
    }

    @Test
    void onFailureHandlerThrowingDoesNotKillTheMonitor(@TempDir Path dir) throws Exception {
        AtomicLong clock = new AtomicLong(1000);
        ThrowingListener l = new ThrowingListener(1, true); // both callback and onFailure throw
        FilesystemMonitor m = new FilesystemMonitor(dir, l, 0, 100, 600_000, clock::get, 4);
        m.openScanExecutorForTest();
        Files.writeString(dir.resolve("A.jar"), "a");

        assertDoesNotThrow(m::reconcileNow);
        awaitTrue(() -> l.attempts.get() >= 1, 3000);
        // The change is still pending (not lost) and the monitor is not FATAL.
        assertTrue(m.pendingCount() >= 1);
        assertNotEquals(MonitorHealth.State.FATAL, m.health().state());
        m.close();
    }

    // --- Phase 1C: watch-key invalidation and recovery ---

    @Test
    void cancelledWatchKeyIsDetectedAndReRegistered(@TempDir Path dir) throws Exception {
        BlockingListener l = new BlockingListener();
        try (FilesystemMonitor m = new FilesystemMonitor(dir, l, 100, 100, 5000, System::currentTimeMillis)) {
            m.start();
            awaitTrue(() -> m.health().state() == MonitorHealth.State.RUNNING, 5000);

            m.invalidateWatchKeyForTest(); // cancel the registration
            assertFalse(m.isWatchKeyValid(), "key is invalid immediately after cancel");

            // The watch loop must detect this and re-register (the directory still exists).
            awaitTrue(m::isWatchKeyValid, 5000);
            awaitTrue(() -> m.health().state() == MonitorHealth.State.RUNNING, 5000);
        }
    }

    @Test
    void deletedWatchedDirectoryDegradesThenRecovers(@TempDir Path parent) throws Exception {
        Path dir = parent.resolve("watched");
        Files.createDirectory(dir);
        BlockingListener l = new BlockingListener();
        FilesystemMonitor m = new FilesystemMonitor(dir, l, 100, 100, 5000, System::currentTimeMillis);
        m.start();
        awaitTrue(() -> m.health().state() == MonitorHealth.State.RUNNING, 5000);
        // Deleting a watched directory is not permitted on every OS while it is open.
        boolean deleted;
        try {
            Files.delete(dir);
            deleted = !Files.exists(dir);
        } catch (IOException e) {
            deleted = false;
        }
        org.junit.jupiter.api.Assumptions.assumeTrue(deleted, "OS did not allow deleting the watched dir");
        try {
            awaitTrue(() -> m.health().state() == MonitorHealth.State.DEGRADED, 5000);
            Files.createDirectory(dir); // it reappears
            awaitTrue(() -> m.health().state() == MonitorHealth.State.RUNNING, 8000);
        } finally {
            m.close();
        }
    }
}
