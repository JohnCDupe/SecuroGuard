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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Phase 1D: quarantine is transactional. A durable PREPARED record is written before
 * the move so any failure after the source moves leaves a recoverable orphan; a
 * failure before the move leaves the source untouched. Symlink sources are refused.
 */
class QuarantineTransactionTest {

    private Path evilJar(InstancePaths paths) throws IOException {
        return TestArchives.writeFile(paths.modsDir(), "evil.jar", TestArchives.fabricModJar("evil", "1.0.0"));
    }

    private long countStored(Path quarantineDir) throws IOException {
        try (Stream<Path> s = Files.list(quarantineDir)) {
            return s.filter(p -> p.getFileName().toString().endsWith(".quarantined")).count();
        }
    }

    @Test
    void hashMismatchAfterMovePreservesRecoverableOrphan(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path evil = evilJar(paths);
        String real = Hashing.sha256(evil);
        Path qDir = paths.quarantineDir().toAbsolutePath().normalize();
        // Bogus destination hash => post-move verification fails.
        QuarantineManager.Hasher faulty = p ->
                p.toAbsolutePath().normalize().startsWith(qDir) ? "0".repeat(64) : Hashing.sha256(p);
        QuarantineManager qm = new QuarantineManager(paths, faulty);

        assertThrows(QuarantineException.class, () -> qm.quarantine(evil, List.of()));
        assertFalse(Files.exists(evil), "atomic move consumed the source; never returned to mods");
        assertEquals(1, countStored(qDir));
        List<QuarantineFailure> failures = qm.listFailures();
        assertEquals(1, failures.size(), "exactly one recoverable orphan (no duplicate from PREPARED)");
        assertEquals("post-move-verify", failures.get(0).failureStage());
        assertEquals(real, failures.get(0).expectedSha256());
        assertTrue(qm.list().isEmpty(), "a failed quarantine is not a restorable item");
    }

    @Test
    void destinationHashIoExceptionAfterMoveIsRecoverableViaPreparedRecord(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path evil = evilJar(paths);
        Path qDir = paths.quarantineDir().toAbsolutePath().normalize();
        // Hashing the destination throws IOException (simulating a read failure after the move).
        QuarantineManager.Hasher faulty = p -> {
            if (p.toAbsolutePath().normalize().startsWith(qDir)) {
                throw new IOException("cannot read destination");
            }
            return Hashing.sha256(p);
        };
        QuarantineManager qm = new QuarantineManager(paths, faulty);

        assertThrows(QuarantineException.class, () -> qm.quarantine(evil, List.of()));
        assertFalse(Files.exists(evil));
        assertEquals(1, countStored(qDir), "the moved file is preserved as the only copy");
        assertEquals(1, qm.listFailures().size(), "orphan is recoverable even though hashing failed");
    }

    @Test
    void sidecarWriteFailureAfterVerifiedMoveIsRecoverable(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path evil = evilJar(paths);
        Path qDir = paths.quarantineDir().toAbsolutePath().normalize();
        QuarantineManager qm = new QuarantineManager(paths);
        qm.failNextSidecarWriteForTest(); // verified move succeeds, then the sidecar write fails

        assertThrows(QuarantineException.class, () -> qm.quarantine(evil, List.of()));
        assertFalse(Files.exists(evil));
        assertEquals(1, countStored(qDir));
        assertEquals(1, qm.listFailures().size(), "orphan recoverable after sidecar write failure");
        assertTrue(qm.list().isEmpty());
    }

    @Test
    void preparedRecordWriteFailureLeavesSourceUntouched(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path evil = evilJar(paths);
        Path qDir = paths.quarantineDir().toAbsolutePath().normalize();
        QuarantineManager qm = new QuarantineManager(paths);
        qm.failNextPreparedWriteForTest(); // transaction cannot even be prepared

        assertThrows(QuarantineException.class, () -> qm.quarantine(evil, List.of()));
        assertTrue(Files.exists(evil), "source must be untouched if the transaction cannot be prepared");
        Files.createDirectories(qDir);
        assertEquals(0, countStored(qDir), "nothing was moved");
        assertTrue(qm.listFailures().isEmpty(), "no orphan when the move never happened");
    }

    @Test
    void symlinkSourceIsRefused(@TempDir Path game, @TempDir Path outside) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Files.createDirectories(paths.modsDir());
        Path realTarget = Files.writeString(outside.resolve("target.jar"), "EXTERNAL");
        Path link = paths.modsDir().resolve("link.jar");
        boolean linked;
        try {
            Files.createSymbolicLink(link, realTarget);
            linked = true;
        } catch (IOException | UnsupportedOperationException e) {
            linked = false;
        }
        assumeTrue(linked, "symlink creation not permitted on this OS/user");

        QuarantineManager qm = new QuarantineManager(paths);
        QuarantineException ex = assertThrows(QuarantineException.class, () -> qm.quarantine(link, List.of()));
        assertTrue(ex.getMessage().toLowerCase().contains("symbolic link")
                || ex.getMessage().toLowerCase().contains("junction"));
        assertTrue(Files.exists(realTarget), "external target must be untouched");
    }

    @Test
    void healthyQuarantineAndRestoreStillWork(@TempDir Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path evil = evilJar(paths);
        String hash = Hashing.sha256(evil);
        QuarantineManager qm = new QuarantineManager(paths);

        QuarantineItem item = qm.quarantine(evil, List.of());
        assertFalse(Files.exists(evil));
        assertEquals(hash, item.sha256());
        assertEquals(1, qm.list().size());
        assertTrue(qm.listFailures().isEmpty(), "a healthy quarantine leaves no orphan");
        // The PREPARED record must have been finalized (removed) on success.
        try (Stream<Path> s = Files.list(paths.quarantineDir())) {
            assertTrue(s.noneMatch(p -> p.getFileName().toString().endsWith(".prepared.json")),
                    "PREPARED record must be removed after a successful quarantine");
        }

        Path restored = qm.restore(item.id(), true);
        assertEquals(evil.normalize(), restored.normalize());
        assertEquals(hash, Hashing.sha256(restored));
        assertTrue(qm.list().isEmpty());
    }
}
