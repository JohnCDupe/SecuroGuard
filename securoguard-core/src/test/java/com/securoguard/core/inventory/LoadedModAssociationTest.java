package com.securoguard.core.inventory;

import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.service.ScanService;
import com.securoguard.core.testutil.TestArchives;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R4: loader-reported {@link InstalledMod} descriptors must reach core inventory
 * records — files matching a mod origin are marked {@code loadedAsMod}, and the
 * association logic is loader-neutral.
 */
class LoadedModAssociationTest {

    @Test
    void indexAssociatesByAbsolutePathAndSkipsSynthetic(@TempDir Path dir) {
        Path a = dir.resolve("mods/a.jar");
        Path b = dir.resolve("mods/b.jar");
        InstalledMod real = new InstalledMod("a", "A", "1.0", "fabric",
                List.of(a.toString()), false, false);
        InstalledMod multi = new InstalledMod("b", "B", "2.0", "fabric",
                List.of(b.toString(), dir.resolve("mods/b-extra.jar").toString()), false, false);
        InstalledMod synthetic = new InstalledMod("minecraft", "Minecraft", "1.21.11", "fabric",
                List.of(), false, true);

        LoadedModIndex index = new LoadedModIndex(List.of(real, multi, synthetic));
        assertTrue(index.forAbsolutePath(a.toString()).isPresent());
        // A mod with multiple origins is found by any of them.
        assertEquals("b", index.forAbsolutePath(b.toString()).get().modId());
        assertEquals("b", index.forAbsolutePath(dir.resolve("mods/b-extra.jar").toString()).get().modId());
        // Synthetic mods contribute no path associations.
        assertEquals(Optional.empty(), index.forAbsolutePath(dir.resolve("nonexistent").toString()));
    }

    @Test
    void indexIgnoresNonDefaultFilesystemOriginsGracefully() {
        // A jar-in-jar origin such as "jar:/foo.jar!/nested.jar" cannot be a default
        // FS path; the index must skip it without throwing.
        InstalledMod nested = new InstalledMod("n", "N", "1", "fabric",
                List.of("jar:file:///x.jar!/nested.jar"), true, false);
        assertDoesNotThrow(() -> new LoadedModIndex(List.of(nested)));
        assertTrue(new LoadedModIndex(List.of(nested)).isEmpty());
    }

    @Test
    void scanServiceMarksLoadedAsModFromDescriptors(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Path sodium = TestArchives.writeFile(paths.modsDir(), "sodium.jar",
                TestArchives.fabricModJar("sodium", "0.6.0"));
        Path unloaded = TestArchives.writeFile(paths.modsDir(), "leftover.jar",
                TestArchives.fabricModJar("leftover", "1.0.0"));

        // Fabric-shaped descriptor: sodium is loaded, leftover.jar is not reported.
        InstalledMod sodiumMod = new InstalledMod("sodium", "Sodium", "0.6.0", "fabric",
                List.of(sodium.toAbsolutePath().normalize().toString()), false, false);

        ScanService svc = new ScanService(paths, RuleEngine.withDefaultRules(), null, Set.of())
                .withLoadedMods(List.of(sodiumMod));

        FileInventory inv = captureCurrentInventory(svc, game);
        assertTrue(inv.get("mods/sodium.jar").loadedAsMod(), "sodium should be marked loaded");
        assertFalse(inv.get("mods/leftover.jar").loadedAsMod(), "leftover should not be marked loaded");
    }

    /** Runs a scan and returns the captured current inventory from the report. */
    private FileInventory captureCurrentInventory(ScanService svc, Path game) throws IOException {
        try {
            return svc.scan(false, false).currentInventory();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }
}
