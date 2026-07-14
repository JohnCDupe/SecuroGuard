package com.securoguard.core.monitor;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class FileSettleTrackerTest {

    private final Path file = Path.of("mods/a.jar");

    @Test
    void fileNotSettledUntilQuietPeriodElapses() {
        FileSettleTracker t = new FileSettleTracker(1000);
        t.observe(file, 100, 1, 0);
        assertTrue(t.drainSettled(500).isEmpty(), "not enough quiet time yet");
        assertEquals(List.of(file), t.drainSettled(1000), "settles exactly at the quiet period");
    }

    @Test
    void changingSizeResetsTheQuietPeriod() {
        FileSettleTracker t = new FileSettleTracker(1000);
        t.observe(file, 100, 1, 0);
        // A modify at t=800 (file still growing) must restart the timer.
        t.observe(file, 200, 2, 800);
        assertTrue(t.drainSettled(1000).isEmpty(), "reset means not settled at old deadline");
        assertEquals(List.of(file), t.drainSettled(1800), "settles 1000ms after the last change");
    }

    @Test
    void repeatedIdenticalObservationsDoNotResetTimer() {
        FileSettleTracker t = new FileSettleTracker(1000);
        t.observe(file, 100, 1, 0);
        t.observe(file, 100, 1, 500); // identical -> debounced, no reset
        assertEquals(List.of(file), t.drainSettled(1000));
    }

    @Test
    void forgetRemovesPendingFile() {
        FileSettleTracker t = new FileSettleTracker(1000);
        t.observe(file, 100, 1, 0);
        t.forget(file);
        assertEquals(0, t.pendingCount());
        assertTrue(t.drainSettled(5000).isEmpty());
    }

    @Test
    void drainRemovesSettledFilesSoTheyAreNotReportedTwice() {
        FileSettleTracker t = new FileSettleTracker(100);
        t.observe(file, 1, 1, 0);
        assertEquals(1, t.drainSettled(200).size());
        assertTrue(t.drainSettled(300).isEmpty(), "already drained");
    }
}
