package com.securoguard.core.quarantine;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.testutil.TestArchives;
import com.securoguard.core.util.Json;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Adversarial tests for {@link QuarantineManager#restore}: a malicious or corrupt
 * sidecar must never be able to cause a write outside the configured instance, and
 * any validation failure must leave the quarantine copy and sidecar intact.
 */
class QuarantineRestoreSecurityTest {

    /** A quarantined fixture: the instance, manager, item, and on-disk paths. */
    private record Fixture(InstancePaths paths, QuarantineManager qm, QuarantineItem item,
                           Path stored, Path sidecar) {
    }

    private Fixture quarantineOne(Path game) throws Exception {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path jar = TestArchives.writeFile(paths.modsDir(), "evil.jar",
                TestArchives.fabricModJar("evil", "1.0.0"));
        QuarantineManager qm = new QuarantineManager(paths);
        QuarantineItem item = qm.quarantine(jar, List.of());
        Path stored = paths.quarantineDir().resolve(item.storedFileName());
        Path sidecar = paths.quarantineDir().resolve(item.storedFileName() + ".json");
        assertTrue(Files.exists(stored));
        assertTrue(Files.exists(sidecar));
        return new Fixture(paths, qm, item, stored, sidecar);
    }

    private void mutateSidecar(Path sidecar, Consumer<JsonObject> mutation) throws IOException {
        JsonObject obj = JsonParser.parseString(Files.readString(sidecar, StandardCharsets.UTF_8)).getAsJsonObject();
        mutation.accept(obj);
        Files.writeString(sidecar, Json.gson().toJson(obj), StandardCharsets.UTF_8);
    }

    private void assertPreserved(Fixture f) {
        assertTrue(Files.exists(f.stored()), "quarantine copy must be preserved after a failed restore");
        assertTrue(Files.exists(f.sidecar()), "sidecar must be preserved after a failed restore");
    }

    // --- 1. absolute outside-instance restoration path ---
    @Test
    void rejectsAbsoluteOutsideInstancePath(@TempDir Path game, @TempDir Path outside) throws Exception {
        Fixture f = quarantineOne(game);
        Path evilTarget = outside.resolve("pwned.jar");
        mutateSidecar(f.sidecar(), o -> {
            o.addProperty("originalRelativePath", evilTarget.toString());
            o.addProperty("originalAbsolutePath", evilTarget.toString());
        });
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertFalse(Files.exists(evilTarget), "must not write outside the instance");
        assertPreserved(f);
    }

    // --- 2. ../ traversal ---
    @Test
    void rejectsTraversalRelativePath(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        mutateSidecar(f.sidecar(), o -> o.addProperty("originalRelativePath", "mods/../../escape.jar"));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertFalse(Files.exists(game.getParent().resolve("escape.jar")));
        assertPreserved(f);
    }

    // --- 3. drive-qualified path (rejected on every OS via the ':' guard) ---
    @Test
    void rejectsDriveQualifiedPath(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        mutateSidecar(f.sidecar(), o -> o.addProperty("originalRelativePath", "C:\\Windows\\Temp\\evil.jar"));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 4. malicious storedFileName (contains separators) ---
    @Test
    void rejectsMaliciousStoredFileName(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        mutateSidecar(f.sidecar(), o -> o.addProperty("storedFileName", "../../evil.quarantined"));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 5. mismatched sidecar id (storedFileName not tied to id) ---
    @Test
    void rejectsIdStoredNameMismatch(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        // Keep a valid-looking basename but break the id/storedFileName binding.
        mutateSidecar(f.sidecar(), o -> o.addProperty("storedFileName", "unrelated-name.quarantined"));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 6. invalid schema version ---
    @Test
    void rejectsUnsupportedSchemaVersion(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        mutateSidecar(f.sidecar(), o -> o.addProperty("schemaVersion", 999));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 7. invalid SHA-256 ---
    @Test
    void rejectsInvalidSha256(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        mutateSidecar(f.sidecar(), o -> o.addProperty("sha256", "not-a-real-hash"));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 8. stored-file hash mismatch ---
    @Test
    void rejectsStoredHashMismatch(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        // Overwrite stored bytes with same length but different content.
        byte[] original = Files.readAllBytes(f.stored());
        byte[] tampered = original.clone();
        tampered[0] ^= 0xFF;
        Files.write(f.stored(), tampered);
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
        assertFalse(Files.exists(game.resolve("mods/evil.jar")), "must not restore a tampered stored file");
    }

    // --- 9. stored-file size mismatch ---
    @Test
    void rejectsStoredSizeMismatch(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        mutateSidecar(f.sidecar(), o -> o.addProperty("size", f.item().size() + 100));
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 10. restore through a symlink stored file (skip if OS forbids symlinks) ---
    @Test
    void refusesSymlinkStoredFile(@TempDir Path game, @TempDir Path outside) throws Exception {
        Fixture f = quarantineOne(game);
        Path realElsewhere = Files.write(outside.resolve("real.bin"), Files.readAllBytes(f.stored()));
        Files.delete(f.stored());
        assumeTrue(trySymlink(f.stored(), realElsewhere), "symlink creation not permitted on this OS/user");
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
    }

    // --- 11. restore through a linked parent directory (skip if OS forbids symlinks) ---
    @Test
    void refusesLinkedParentDirectory(@TempDir Path game, @TempDir Path outside) throws Exception {
        Fixture f = quarantineOne(game);
        // Replace mods/ with a symlink to an outside directory.
        Files.delete(game.resolve("mods")); // empty after the file was quarantined
        assumeTrue(trySymlink(game.resolve("mods"), outside), "symlink creation not permitted on this OS/user");
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertFalse(Files.exists(outside.resolve("evil.jar")), "must not restore through a linked parent");
        assertPreserved(f);
    }

    // --- 12. missing target parent ---
    @Test
    void refusesWhenTargetParentMissing(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        Files.delete(game.resolve("mods")); // remove the parent dir entirely
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 13. existing target refusal ---
    @Test
    void refusesExistingTarget(@TempDir Path game) throws Exception {
        Fixture f = quarantineOne(game);
        Files.write(game.resolve("mods/evil.jar"), new byte[]{1, 2, 3}); // occupy the target
        assertThrows(QuarantineException.class, () -> f.qm().restore(f.item().id(), true));
        assertPreserved(f);
    }

    // --- 14. successful safe restoration (and originalAbsolutePath is ignored) ---
    @Test
    void successfulSafeRestorationIgnoresAbsolutePath(@TempDir Path game, @TempDir Path outside) throws Exception {
        Fixture f = quarantineOne(game);
        Path decoy = outside.resolve("decoy.jar");
        // Point the (untrusted) absolute field outside the instance; relative stays valid.
        mutateSidecar(f.sidecar(), o -> o.addProperty("originalAbsolutePath", decoy.toString()));
        Path restored = f.qm().restore(f.item().id(), true);
        assertEquals(game.resolve("mods/evil.jar").normalize(), restored.normalize());
        assertTrue(Files.exists(game.resolve("mods/evil.jar")));
        assertFalse(Files.exists(decoy), "originalAbsolutePath must never be used as the target");
        assertFalse(Files.exists(f.stored()), "quarantine copy removed after verified restore");
        assertFalse(Files.exists(f.sidecar()), "sidecar removed after verified restore");
    }

    private static boolean trySymlink(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
            return true;
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }
}
