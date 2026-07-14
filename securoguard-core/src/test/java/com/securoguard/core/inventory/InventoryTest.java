package com.securoguard.core.inventory;

import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.util.Hashing;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class InventoryTest {

    @Test
    void sha256MatchesKnownVector() {
        // NIST/well-known vector for "abc".
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                Hashing.sha256("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void scannerHashesAndClassifiesModsFiles(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        Files.createDirectories(paths.modsDir());
        Path jar = paths.modsDir().resolve("example.jar");
        byte[] content = new byte[]{0x50, 0x4B, 0x03, 0x04, 1, 2, 3, 4};
        Files.write(jar, content);

        FileInventory inv = new InventoryScanner(paths).scanInstance();
        FileRecord rec = inv.get("mods/example.jar");

        assertNotNull(rec, "expected the jar to be inventoried under its relative path");
        assertEquals("example.jar", rec.fileName());
        assertTrue(rec.inModsDir());
        assertEquals(Hashing.sha256(jar), rec.sha256());
        assertEquals(FileType.ZIP_ARCHIVE, rec.detectedType());
        assertEquals(content.length, rec.size());
    }

    @Test
    void scannerSkipsSecuroGuardDataDirectory(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        paths.createDataDirectories();
        Files.write(paths.dataDir().resolve("baseline.json"), "{}".getBytes(StandardCharsets.UTF_8));

        FileInventory inv = new InventoryScanner(paths).scanInstance();
        // SecuroGuard's own data must not appear in the instance inventory.
        assertTrue(inv.records().stream().noneMatch(r -> r.relativePath().startsWith("securoguard/")));
    }

    @Test
    void diffDetectsAddedRemovedModifiedRenamed() {
        FileRecord a = rec("mods/a.jar", "hashA", 10);
        FileRecord b = rec("mods/b.jar", "hashB", 20);
        FileRecord bMod = rec("mods/b.jar", "hashB2", 25);
        FileRecord c = rec("mods/c.jar", "hashC", 30);
        FileRecord cRenamed = rec("mods/c-renamed.jar", "hashC", 30); // same content, new path

        FileInventory baseline = FileInventory.of(java.util.List.of(a, b, c));
        FileInventory current = FileInventory.of(java.util.List.of(bMod, cRenamed,
                rec("mods/new.jar", "hashNew", 40)));

        DiffResult diff = InventoryDiff.compute(baseline, current);

        assertEquals(1, diff.added().size(), "new.jar is added");
        assertEquals("mods/new.jar", diff.added().get(0).relativePath());
        assertEquals(1, diff.removed().size(), "a.jar removed");
        assertEquals("mods/a.jar", diff.removed().get(0).relativePath());
        assertEquals(1, diff.modified().size(), "b.jar modified in place");
        assertEquals(1, diff.renamed().size(), "c.jar -> c-renamed.jar inferred as rename");
        assertEquals("mods/c.jar", diff.renamed().get(0).from().relativePath());
        assertEquals("mods/c-renamed.jar", diff.renamed().get(0).to().relativePath());
    }

    private static FileRecord rec(String rel, String hash, long size) {
        return new FileRecord("/abs/" + rel, rel, rel.substring(rel.lastIndexOf('/') + 1),
                size, 0L, hash, FileType.ZIP_ARCHIVE, rel.startsWith("mods/"), false);
    }
}
