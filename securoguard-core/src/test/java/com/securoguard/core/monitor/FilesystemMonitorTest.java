package com.securoguard.core.monitor;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class FilesystemMonitorTest {

    /** Records callbacks in a thread-safe way for assertions. */
    static final class RecordingListener implements MonitorListener {
        final CopyOnWriteArrayList<Path> settled = new CopyOnWriteArrayList<>();
        final CopyOnWriteArrayList<Path> removed = new CopyOnWriteArrayList<>();
        final AtomicReference<Set<Path>> lastReconciled = new AtomicReference<>();
        final CopyOnWriteArrayList<String> failures = new CopyOnWriteArrayList<>();
        volatile CountDownLatch settledLatch = new CountDownLatch(1);

        @Override
        public void onFileSettled(Path file) {
            settled.add(file);
            settledLatch.countDown();
        }

        @Override
        public void onFileRemoved(Path file) {
            removed.add(file);
        }

        @Override
        public void onReconciled(Set<Path> currentFiles) {
            lastReconciled.set(currentFiles);
        }

        @Override
        public void onFailure(String message, Throwable cause, boolean fatal) {
            failures.add(message);
        }
    }

    @Test
    void detectsANewFileAfterItSettles(@TempDir Path dir) throws Exception {
        RecordingListener listener = new RecordingListener();
        try (FilesystemMonitor monitor = new FilesystemMonitor(dir, listener, 200, 100, 5000,
                System::currentTimeMillis)) {
            monitor.start();
            Files.write(dir.resolve("added.jar"), new byte[]{1, 2, 3});

            assertTrue(listener.settledLatch.await(10, TimeUnit.SECONDS),
                    "monitor should report the new file once it settles");
            assertTrue(listener.settled.stream().anyMatch(p -> p.getFileName().toString().equals("added.jar")));
            assertTrue(listener.failures.isEmpty(), "no failures expected: " + listener.failures);
        }
    }

    @Test
    void overflowTriggersFullReconciliation(@TempDir Path dir) throws Exception {
        RecordingListener listener = new RecordingListener();
        // Long quiet period so the file does not settle on its own during the test.
        try (FilesystemMonitor monitor = new FilesystemMonitor(dir, listener, 60_000, 100, 60_000,
                System::currentTimeMillis)) {
            monitor.start();
            Files.write(dir.resolve("recovered.jar"), new byte[]{9});
            // Simulate a dropped-events OVERFLOW; the monitor must fully rescan.
            monitor.simulateOverflow();

            Set<Path> reconciled = listener.lastReconciled.get();
            assertNotNull(reconciled, "reconciliation should have produced a current set");
            assertTrue(reconciled.stream().anyMatch(p -> p.getFileName().toString().equals("recovered.jar")),
                    "reconciliation after overflow must include the missed file");
        }
    }

    @Test
    void reportsRemovalOfWatchedFile(@TempDir Path dir) throws Exception {
        RecordingListener listener = new RecordingListener();
        Path file = dir.resolve("gone.jar");
        Files.write(file, new byte[]{1});
        try (FilesystemMonitor monitor = new FilesystemMonitor(dir, listener, 100, 100, 5000,
                System::currentTimeMillis)) {
            monitor.start();
            Thread.sleep(300);
            Files.delete(file);
            // Poll for the delete event.
            long deadline = System.currentTimeMillis() + 10_000;
            while (listener.removed.isEmpty() && System.currentTimeMillis() < deadline) {
                Thread.sleep(100);
            }
            assertTrue(listener.removed.stream().anyMatch(p -> p.getFileName().toString().equals("gone.jar")));
        }
    }
}
