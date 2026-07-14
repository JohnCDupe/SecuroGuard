package com.securoguard.core.advisory;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.inventory.InstalledMod;
import com.securoguard.core.service.ScanReport;
import com.securoguard.core.service.ScanService;
import com.securoguard.core.testutil.TestArchives;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R2: advisory matching wired into real scans through {@link ScanService}, using
 * the bundled Litematica/Servux feed.
 */
class AdvisoryScanIntegrationTest {

    private ScanService service(InstancePaths paths, String mcVersion) {
        return new ScanService(paths, RuleEngine.withDefaultRules(), null, Set.of())
                .withAdvisorySource(new BundledAdvisorySource())
                .withMinecraftVersion(mcVersion);
    }

    private List<Finding> scanAfterApprove(ScanService svc) throws Exception {
        svc.approveCurrentAsBaseline(); // trust current files so only advisory findings remain
        ScanReport report = svc.scan(false, false);
        return report.findings();
    }

    private boolean hasAdvisory(List<Finding> findings) {
        return findings.stream().anyMatch(f -> f.ruleId().equals("SG-ADVISORY"));
    }

    @Test
    void missingMinecraftVersionEmitsOneIncompleteFindingNotAVulnerability(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "litematica.jar",
                TestArchives.fabricModJar("litematica", "0.26.10"));
        TestArchives.writeFile(paths.modsDir(), "servux.jar",
                TestArchives.fabricModJar("servux", "0.9.4"));
        // No Minecraft version supplied.
        List<Finding> findings = scanAfterApprove(service(paths, null));
        assertFalse(hasAdvisory(findings), "must NOT emit a vulnerability finding when MC version is unknown");
        long incomplete = findings.stream().filter(f -> f.ruleId().equals("SG-ADVISORY-INCOMPLETE")).count();
        assertEquals(1, incomplete, "exactly one aggregate incomplete-info finding (not one per advisory)");
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("SG-ADVISORY-INCOMPLETE")
                && f.evidence().contains("Minecraft version")));
    }

    @Test
    void invalidSignatureEmitsOneDegradedProtectionFinding(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "litematica.jar",
                TestArchives.fabricModJar("litematica", "0.26.10"));
        // A verified source whose signature will not verify (garbage key/sig).
        java.security.KeyPair kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        VerifiedAdvisorySource bad = new VerifiedAdvisorySource(
                AdvisoryFeeds.bundledFeedBytes(), new byte[64], kp.getPublic());
        ScanService svc = new ScanService(paths, RuleEngine.withDefaultRules(), null, Set.of())
                .withAdvisorySource(bad).withMinecraftVersion("1.21.11");
        List<Finding> findings = scanAfterApprove(svc);
        assertFalse(hasAdvisory(findings), "a failed feed must NOT silently mark files safe");
        long degraded = findings.stream().filter(f -> f.ruleId().equals("SG-ADVISORY-UNAVAILABLE")).count();
        assertEquals(1, degraded, "exactly one degraded-protection finding");
        assertEquals(Severity.MEDIUM, findings.stream()
                .filter(f -> f.ruleId().equals("SG-ADVISORY-UNAVAILABLE")).findFirst().orElseThrow().severity());
    }

    @Test
    void affectedLitematicaVersionProducesFinding(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "litematica.jar",
                TestArchives.fabricModJar("litematica", "0.26.10")); // < 0.26.11 fix for 1.21.11
        List<Finding> findings = scanAfterApprove(service(paths, "1.21.11"));
        assertTrue(hasAdvisory(findings), "an affected Litematica version must be flagged");
        Finding adv = findings.stream().filter(f -> f.ruleId().equals("SG-ADVISORY")).findFirst().orElseThrow();
        assertEquals(Severity.HIGH, adv.severity());
        assertTrue(adv.evidence().contains("0.26.11"), "evidence should include the fixed version");
    }

    @Test
    void fixedLitematicaVersionDoesNotMatch(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "litematica.jar",
                TestArchives.fabricModJar("litematica", "0.26.11")); // patched for 1.21.11
        assertFalse(hasAdvisory(scanAfterApprove(service(paths, "1.21.11"))));
    }

    @Test
    void differentMinecraftLineUsesItsOwnBoundary(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "litematica.jar",
                TestArchives.fabricModJar("litematica", "0.21.6")); // affected on 1.21.4 (fix 0.21.7)
        assertTrue(hasAdvisory(scanAfterApprove(service(paths, "1.21.4"))));

        InstancePaths paths2 = InstancePaths.ofGameDir(game.resolve("other"));
        TestArchives.writeFile(paths2.modsDir(), "litematica.jar",
                TestArchives.fabricModJar("litematica", "0.21.7")); // patched on 1.21.4
        assertFalse(hasAdvisory(scanAfterApprove(service(paths2, "1.21.4"))));
    }

    @Test
    void unrelatedModsDoNotMatch(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "sodium.jar",
                TestArchives.fabricModJar("sodium", "0.6.0"));
        assertFalse(hasAdvisory(scanAfterApprove(service(paths, "1.21.11"))));
    }

    @Test
    void fabricSuppliedCoordinatesReachTheMatcher(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        // The jar's own metadata says "notlitematica"; the loader descriptor says it
        // is litematica 0.26.10. The advisory must match via the loader coordinates.
        Path jar = TestArchives.writeFile(paths.modsDir(), "obf.jar",
                TestArchives.fabricModJar("notlitematica", "9.9.9"));
        InstalledMod descriptor = new InstalledMod("litematica", "Litematica", "0.26.10", "fabric",
                List.of(jar.toAbsolutePath().normalize().toString()), false, false);

        ScanService svc = service(paths, "1.21.11").withLoadedMods(List.of(descriptor));
        assertTrue(hasAdvisory(scanAfterApprove(svc)),
                "loader-supplied coordinates must reach the advisory matcher");
    }

    @Test
    void malformedVersionDoesNotCrashScan(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        TestArchives.writeFile(paths.modsDir(), "weird.jar",
                TestArchives.fabricModJar("litematica", "not-a-version"));
        // Should complete without throwing; version parsing is permissive.
        assertDoesNotThrow(() -> scanAfterApprove(service(paths, "1.21.11")));
    }
}
