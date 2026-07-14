package com.securoguard.core.integration;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.monitor.FilesystemMonitor;
import com.securoguard.core.monitor.MonitorListener;
import com.securoguard.core.quarantine.QuarantineItem;
import com.securoguard.core.quarantine.QuarantineManager;
import com.securoguard.core.reputation.MapReputationProvider;
import com.securoguard.core.service.ScanReport;
import com.securoguard.core.service.ScanService;
import com.securoguard.core.testutil.TestArchives;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The headline vertical slice: a harmless JAR dropped into {@code mods} during an
 * active, "connected" session produces a CRITICAL finding via the live monitor,
 * and can then be safely quarantined and verified.
 */
class EndToEndScenarioTest {

    @Test
    void newJarDuringSessionIsCriticalThenQuarantined(@TempDir Path game) throws Exception {
        // 1. Fake Minecraft instance with one pre-existing, approved mod.
        InstancePaths paths = InstancePaths.ofGameDir(game);
        paths.createDataDirectories();
        TestArchives.writeFile(paths.modsDir(), "sodium.jar", TestArchives.fabricModJar("sodium", "0.6.0"));

        ScanService scanService = new ScanService(paths, RuleEngine.withDefaultRules(),
                new MapReputationProvider(), Set.of());

        // 2. Establish the trusted baseline (explicit approval).
        scanService.approveCurrentAsBaseline();

        // A cold scan right after approval finds nothing.
        assertTrue(scanService.scan(false, false).findings().stream()
                .noneMatch(f -> f.severity() == Severity.CRITICAL));

        // 3. Start the monitor; on each settled file, run a full scan and capture a critical finding.
        AtomicReference<Finding> criticalFinding = new AtomicReference<>();
        AtomicReference<Path> criticalPath = new AtomicReference<>();
        CountDownLatch criticalLatch = new CountDownLatch(1);

        MonitorListener listener = new MonitorListener() {
            @Override
            public void onFileSettled(Path file) {
                try {
                    ScanReport report = scanService.scan(true, true); // sessionActive + connected
                    report.findings().stream()
                            .filter(f -> f.severity() == Severity.CRITICAL)
                            .findFirst()
                            .ifPresent(f -> {
                                if (criticalFinding.compareAndSet(null, f)) {
                                    criticalPath.set(file);
                                    criticalLatch.countDown();
                                }
                            });
                } catch (Exception e) {
                    fail("scan during monitoring threw: " + e);
                }
            }

            @Override public void onFileRemoved(Path file) { }
            @Override public void onReconciled(Set<Path> currentFiles) { }
            @Override public void onFailure(String message, Throwable cause, boolean fatal) {
                fail("monitor failure: " + message + " / " + cause);
            }
        };

        try (FilesystemMonitor monitor = new FilesystemMonitor(paths.modsDir(), listener,
                200, 100, 5000, System::currentTimeMillis)) {
            monitor.start();

            // 4. A malicious-looking (but harmless) JAR is written into mods mid-session.
            Path malicious = TestArchives.writeFile(paths.modsDir(), "totally_safe.litematic.jar",
                    TestArchives.fabricModJar("sneaky", "6.6.6"));
            String maliciousHash = Hashing.sha256(malicious);

            // 5. Expect a CRITICAL finding.
            assertTrue(criticalLatch.await(15, TimeUnit.SECONDS),
                    "a critical finding should be raised for the new in-session JAR");
            assertEquals(Severity.CRITICAL, criticalFinding.get().severity());

            // 6. Quarantine the file (explicit action).
            QuarantineManager qm = new QuarantineManager(paths);
            QuarantineItem item = qm.quarantine(malicious, scanService.scan(true, true).findings());

            // 7. It is no longer in mods.
            assertFalse(Files.exists(malicious), "quarantined jar must be gone from mods");
            assertTrue(Files.list(paths.modsDir()).noneMatch(p -> p.getFileName().toString().endsWith(".litematic.jar")));

            // 8. Its hash and quarantine metadata are verified and preserved.
            Path stored = paths.quarantineDir().resolve(item.storedFileName());
            assertEquals(maliciousHash, item.sha256());
            assertEquals(maliciousHash, Hashing.sha256(stored));
            assertFalse(item.triggeringFindings().isEmpty());
            assertTrue(item.triggeringFindings().stream()
                    .anyMatch(t -> t.ruleId().equals("SG-NEW-JAR-IN-SESSION")));
        }
    }
}
