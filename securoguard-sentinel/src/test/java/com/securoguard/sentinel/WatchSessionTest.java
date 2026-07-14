package com.securoguard.sentinel;

import com.securoguard.core.advisory.BundledAdvisorySource;
import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.service.ScanService;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RB4: deterministic tests for the Sentinel watch behaviour via {@link WatchSession},
 * with no real monitor and no blocking join.
 */
class WatchSessionTest {

    private Path modJar(Path dir, String name, String id, byte[] extra) throws IOException {
        Files.createDirectories(dir);
        Path p = dir.resolve(name);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bos)) {
            zip.putNextEntry(new ZipEntry("fabric.mod.json"));
            zip.write(("{\"schemaVersion\":1,\"id\":\"" + id + "\",\"version\":\"1.0.0\"}")
                    .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
            if (extra != null) {
                zip.putNextEntry(new ZipEntry("extra.bin"));
                zip.write(extra);
                zip.closeEntry();
            }
        }
        Files.write(p, bos.toByteArray());
        return p;
    }

    private ScanService service(InstancePaths paths, Set<String> malicious) {
        return new ScanService(paths, RuleEngine.withDefaultRules(), null, malicious)
                .withAdvisorySource(new BundledAdvisorySource())
                .withDefaultScope(ScanScope.RUNTIME);
    }

    private record Harness(WatchSession session, ByteArrayOutputStream out) {
        String text() {
            return out.toString(StandardCharsets.UTF_8);
        }
        void reset() {
            out.reset();
        }
    }

    private Harness harness(InstancePaths paths, ScanService svc, Severity min, boolean redact) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        return new Harness(new WatchSession(svc, new PrintStream(bos, true, StandardCharsets.UTF_8),
                paths, redact, min), bos);
    }

    @Test
    void newHighRiskJarProducesHighAlert(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        ScanService svc = service(paths, Set.of());
        svc.approveCurrentAsBaseline(ScanScope.RUNTIME); // empty mods baseline
        Harness h = harness(paths, svc, Severity.HIGH, false);
        h.session.onChange(); // baseline pass, no alerts

        modJar(paths.modsDir(), "sneaky.jar", "sneaky", null);
        h.reset();
        int raised = h.session.onChange();

        assertTrue(raised >= 1, "a new untrusted JAR (HIGH) must alert at the default threshold");
        assertTrue(h.text().contains("[ALERT HIGH]"), h.text());
        assertTrue(h.text().contains("SG-NEW-UNTRUSTED-JAR"), h.text());
    }

    @Test
    void knownMaliciousHashProducesCriticalAlert(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path jar = modJar(paths.modsDir(), "evil.jar", "evil", null);
        String hash = Hashing.sha256(jar);
        Files.delete(jar); // approve an empty baseline first
        ScanService svc = service(paths, Set.of(hash));
        svc.approveCurrentAsBaseline(ScanScope.RUNTIME);

        modJar(paths.modsDir(), "evil.jar", "evil", null); // recreate identical -> same hash
        Harness h = harness(paths, svc, Severity.HIGH, false);
        int raised = h.session.onChange();
        assertTrue(raised >= 1);
        assertTrue(h.text().contains("[ALERT CRITICAL]"), h.text());
        assertTrue(h.text().contains("SG-KNOWN-MALICIOUS-HASH"), h.text());
    }

    @Test
    void infoFindingsHiddenAtDefaultThresholdButShownWhenLowered(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        ScanService svc = service(paths, Set.of());
        svc.approveCurrentAsBaseline(ScanScope.RUNTIME);
        modJar(paths.modsDir(), "mystery.jar", "mystery", null);

        Harness high = harness(paths, svc, Severity.HIGH, false);
        high.session.onChange();
        assertFalse(high.text().contains("SG-UNKNOWN-HASH"), "INFO must be hidden at HIGH threshold");

        Harness info = harness(paths, svc, Severity.INFO, false);
        info.session.onChange();
        assertTrue(info.text().contains("SG-UNKNOWN-HASH"), "lowering the threshold shows INFO");
    }

    @Test
    void unchangedFindingIsNotPrintedTwice(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        ScanService svc = service(paths, Set.of());
        svc.approveCurrentAsBaseline(ScanScope.RUNTIME);
        modJar(paths.modsDir(), "sneaky.jar", "sneaky", null);

        Harness h = harness(paths, svc, Severity.HIGH, false);
        assertTrue(h.session.onChange() >= 1);
        h.reset();
        int secondRaised = h.session.onChange();
        assertEquals(0, secondRaised, "the same unchanged finding must not re-alert");
        assertFalse(h.text().contains("[ALERT"), "no new alert lines on an unchanged rescan");
    }

    @Test
    void changedHashReAlerts(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        ScanService svc = service(paths, Set.of());
        svc.approveCurrentAsBaseline(ScanScope.RUNTIME);
        modJar(paths.modsDir(), "sneaky.jar", "sneaky", new byte[]{1});

        Harness h = harness(paths, svc, Severity.HIGH, false);
        assertTrue(h.session.onChange() >= 1);
        h.reset();
        // Rewrite with different content -> different SHA-256 -> new evidence -> new alert.
        modJar(paths.modsDir(), "sneaky.jar", "sneaky", new byte[]{2, 2, 2, 2});
        int raised = h.session.onChange();
        assertTrue(raised >= 1, "a changed hash must be treated as new evidence and re-alerted");
    }

    @Test
    void redactionAppliesToWatchOutput(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        ScanService svc = service(paths, Set.of());
        svc.approveCurrentAsBaseline(ScanScope.RUNTIME);
        modJar(paths.modsDir(), "sneaky.jar", "sneaky", null);
        Harness h = harness(paths, svc, Severity.HIGH, true);
        h.session.onChange();
        assertFalse(h.text().contains(game.toString()), "absolute instance path must be redacted");
    }
}
