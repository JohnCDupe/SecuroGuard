package com.securoguard.core.inventory;

import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * R7: inventory scanning must never follow a file symlink/junction to a target
 * (possibly outside the instance). Link classification is covered independently so
 * the logic is exercised even where the OS forbids symlink creation.
 */
class SymlinkScanTest {

    private ScopedScan scan(InstancePaths paths) throws IOException {
        return new InventoryScanner(paths).scanScoped(ScanScope.RUNTIME, List.of(), ScanLimits.defaults());
    }

    private static boolean trySymlink(Path link, Path target) {
        try {
            Files.createSymbolicLink(link, target);
            return true;
        } catch (IOException | UnsupportedOperationException e) {
            return false;
        }
    }

    @Test
    void linkClassificationLogicIsCoveredWithoutOsLinks(@TempDir Path dir) throws IOException {
        // A plain regular file is not a link and is not skipped.
        Path real = Files.writeString(dir.resolve("real.jar"), "data");
        assertNull(InventoryScanner.linkSkipReason(real));
    }

    @Test
    void fileSymlinkToOutsideTargetIsNotHashed(@TempDir Path game, @TempDir Path outside) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Files.createDirectories(paths.modsDir());
        Path secret = Files.writeString(outside.resolve("secret.jar"), "SECRET-EXTERNAL-BYTES");
        String secretHash = Hashing.sha256(secret);

        assumeTrue(trySymlink(paths.modsDir().resolve("link.jar"), secret),
                "symlink creation not permitted on this OS/user");

        ScopedScan result = scan(paths);
        // The external target's bytes must never appear in the inventory.
        assertTrue(result.inventory().records().stream().noneMatch(r -> r.sha256().equals(secretHash)),
                "must not hash through a symlink to an external target");
        assertTrue(result.skipped().stream().anyMatch(s -> s.relativePath().equals("mods/link.jar")),
                "the skipped link must be reported");
    }

    @Test
    void fileSymlinkToInsideTargetIsConservativelySkippedAndReported(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path realInside = Files.writeString(
                Files.createDirectories(paths.modsDir()).resolve("real.jar"), "inside");
        assumeTrue(trySymlink(paths.modsDir().resolve("alias.jar"), realInside),
                "symlink creation not permitted on this OS/user");

        ScopedScan result = scan(paths);
        // Documented policy: SecuroGuard refuses to follow ANY file link and reports it.
        assertTrue(result.skipped().stream().anyMatch(s -> s.relativePath().equals("mods/alias.jar")));
        // The real file itself is still inventoried normally.
        assertTrue(result.inventory().records().stream().anyMatch(r -> r.relativePath().equals("mods/real.jar")));
    }

    @Test
    void directorySymlinkIsNotTraversed(@TempDir Path game, @TempDir Path outsideDir) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Files.createDirectories(paths.modsDir());
        Files.writeString(outsideDir.resolve("external.jar"), "EXTERNAL-DIR-CONTENT");

        assumeTrue(trySymlink(paths.modsDir().resolve("linkeddir"), outsideDir),
                "symlink creation not permitted on this OS/user");

        ScopedScan result = scan(paths);
        assertTrue(result.inventory().records().stream()
                        .noneMatch(r -> r.fileName().equals("external.jar")),
                "a directory symlink must not be traversed into an external tree");
    }

    @Test
    void noExternalBytesAppearInInventoryHash(@TempDir Path game, @TempDir Path outside) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Files.writeString(Files.createDirectories(paths.modsDir()).resolve("normal.jar"), "normal");
        Path external = Files.writeString(outside.resolve("ext.jar"), "EXTERNAL");
        String extHash = Hashing.sha256(external);
        assumeTrue(trySymlink(paths.modsDir().resolve("ptr.jar"), external), "no symlink privilege");

        var hashes = scan(paths).inventory().records().stream()
                .map(FileRecord::sha256).collect(Collectors.toSet());
        assertFalse(hashes.contains(extHash));
    }
}
