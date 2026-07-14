package com.securoguard.core.quarantine;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RecommendedAction;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.testutil.TestArchives;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class QuarantineManagerTest {

    private Finding finding() {
        return Finding.builder("SG-NEW-JAR-IN-SESSION", Severity.CRITICAL)
                .title("test").recommend(RecommendedAction.QUARANTINE).build();
    }

    @Test
    void quarantineMovesFileVerifiesHashAndWritesSidecar(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path jar = TestArchives.writeFile(paths.modsDir(), "evil.jar",
                TestArchives.fabricModJar("evil", "1.0.0"));
        String originalHash = Hashing.sha256(jar);

        QuarantineManager qm = new QuarantineManager(paths);
        QuarantineItem item = qm.quarantine(jar, List.of(finding()));

        // Original is gone from mods; a verified copy lives in quarantine.
        assertFalse(Files.exists(jar), "original must be removed from mods after verified move");
        Path stored = paths.quarantineDir().resolve(item.storedFileName());
        assertTrue(Files.exists(stored));
        assertEquals(originalHash, item.sha256());
        assertEquals(originalHash, Hashing.sha256(stored), "quarantined bytes must match original");
        // Not loadable as a mod: outside mods dir and not a .jar.
        assertFalse(item.storedFileName().endsWith(".jar"));
        assertTrue(stored.startsWith(paths.quarantineDir()));

        // Sidecar records the triggering finding.
        assertEquals(1, item.triggeringFindings().size());
        assertEquals("SG-NEW-JAR-IN-SESSION", item.triggeringFindings().get(0).ruleId());
    }

    @Test
    void listAndRestoreRoundTrip(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path jar = TestArchives.writeFile(paths.modsDir(), "restore-me.jar",
                TestArchives.fabricModJar("restoreme", "1.0.0"));
        String originalHash = Hashing.sha256(jar);

        QuarantineManager qm = new QuarantineManager(paths);
        QuarantineItem item = qm.quarantine(jar, List.of(finding()));
        assertEquals(1, qm.list().size());

        Path restored = qm.restore(item.id(), true);
        assertEquals(jar.normalize(), restored.normalize());
        assertTrue(Files.exists(jar));
        assertEquals(originalHash, Hashing.sha256(jar), "restored file must be byte-identical");
        assertTrue(qm.list().isEmpty(), "sidecar removed after restore");
    }

    @Test
    void restoreRequiresConfirmation(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path jar = TestArchives.writeFile(paths.modsDir(), "x.jar", TestArchives.fabricModJar("x", "1"));
        QuarantineManager qm = new QuarantineManager(paths);
        QuarantineItem item = qm.quarantine(jar, List.of(finding()));
        assertThrows(QuarantineException.class, () -> qm.restore(item.id(), false));
    }

    @Test
    void refusesToQuarantineFileOutsideInstance(@TempDir Path game, @TempDir Path outside) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path external = TestArchives.writeFile(outside, "external.jar", TestArchives.fabricModJar("e", "1"));
        QuarantineManager qm = new QuarantineManager(paths);
        // Containment check prevents moving arbitrary system files.
        assertThrows(QuarantineException.class, () -> qm.quarantine(external, List.of(finding())));
        assertTrue(Files.exists(external), "external file must be left untouched");
    }

    @Test
    void restoreWillNotOverwriteExistingFile(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path jar = TestArchives.writeFile(paths.modsDir(), "dup.jar", TestArchives.fabricModJar("dup", "1"));
        QuarantineManager qm = new QuarantineManager(paths);
        QuarantineItem item = qm.quarantine(jar, List.of(finding()));
        // Recreate a file at the original path; restore must refuse to clobber it.
        Files.write(jar, new byte[]{9, 9, 9});
        assertThrows(QuarantineException.class, () -> qm.restore(item.id(), true));
    }
}
