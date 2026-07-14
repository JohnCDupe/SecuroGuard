package com.securoguard.core.quarantine;

import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.testutil.TestArchives;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R8: a post-move verification mismatch must leave a recoverable orphan (the moved
 * file is the only remaining copy) plus a failure record, never delete it and never
 * silently return it to mods.
 */
class QuarantineFailureTest {

    @Test
    void atomicMovePostVerifyMismatchPreservesOrphanAndFailureRecord(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path evil = TestArchives.writeFile(paths.modsDir(), "evil.jar",
                TestArchives.fabricModJar("evil", "1.0.0"));
        String realHash = Hashing.sha256(evil);
        Path quarantineDir = paths.quarantineDir().toAbsolutePath().normalize();

        // Fault-injected hasher: real hash for the source, a bogus hash for anything in
        // the quarantine directory -> simulates a post-move verification mismatch.
        QuarantineManager.Hasher faulty = p -> {
            if (p.toAbsolutePath().normalize().startsWith(quarantineDir)) {
                return "0".repeat(64);
            }
            return Hashing.sha256(p);
        };
        QuarantineManager qm = new QuarantineManager(paths, faulty);

        QuarantineException ex = assertThrows(QuarantineException.class, () -> qm.quarantine(evil, List.of()));
        assertTrue(ex.getMessage().contains("orphan") || ex.getMessage().contains("post-move"),
                "message should explain the recoverable failure: " + ex.getMessage());

        // Source consumed by the atomic move (not returned to mods).
        assertFalse(Files.exists(evil), "the file must NOT be silently returned to mods");

        // The orphan (moved file) is preserved, and there is a failure record.
        long orphans;
        try (Stream<Path> s = Files.list(quarantineDir)) {
            orphans = s.filter(p -> p.getFileName().toString().endsWith(".quarantined")).count();
        }
        assertEquals(1, orphans, "the moved file must be preserved as the only remaining copy");

        List<QuarantineFailure> failures = qm.listFailures();
        assertEquals(1, failures.size(), "listFailures() must surface the orphan");
        QuarantineFailure f = failures.get(0);
        assertEquals("mods/evil.jar", f.originalRelativePath());
        assertEquals(realHash, f.expectedSha256());
        assertEquals("0".repeat(64), f.observedSha256());
        assertEquals("post-move-verify", f.failureStage());

        // A failed quarantine is NOT a normal restorable item.
        assertTrue(qm.list().isEmpty(), "a failed quarantine must not appear as a normal item");
    }

    @Test
    void listFailuresIsEmptyForHealthyManager(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        assertTrue(new QuarantineManager(paths).listFailures().isEmpty());
    }
}
