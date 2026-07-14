package com.securoguard.core.baseline;

import com.securoguard.core.inventory.FileInventory;
import com.securoguard.core.inventory.FileRecord;
import com.securoguard.core.inventory.FileType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class BaselineStoreTest {

    private BaselineStore store(Path game) {
        return new BaselineStore(game.resolve("securoguard/baseline.json"), game);
    }

    @Test
    void savesAndReloadsRoundTrip(@TempDir Path game) throws Exception {
        BaselineStore store = store(game);
        FileRecord r = new FileRecord(game.resolve("mods/a.jar").toString(), "mods/a.jar", "a.jar",
                123, 456, "deadbeef", FileType.ZIP_ARCHIVE, true, false);
        store.save(Baseline.create(FileInventory.of(List.of(r)), com.securoguard.core.instance.ScanScope.FULL));

        Optional<Baseline> loaded = store.load();
        assertTrue(loaded.isPresent());
        FileRecord back = loaded.get().inventory().get("mods/a.jar");
        assertNotNull(back);
        assertEquals("deadbeef", back.sha256());
        assertEquals(123, back.size());
        assertTrue(back.inModsDir());
        // Absolute path is reconstructed from the current game dir, not stored verbatim.
        assertEquals(game.resolve("mods/a.jar").normalize().toString(), back.absolutePath());
    }

    @Test
    void missingBaselineIsEmptyNotError(@TempDir Path game) throws Exception {
        assertTrue(store(game).load().isEmpty());
    }

    @Test
    void atomicSaveLeavesNoTempFiles(@TempDir Path game) throws Exception {
        BaselineStore store = store(game);
        store.save(Baseline.create(FileInventory.empty(), com.securoguard.core.instance.ScanScope.FULL));
        Path dir = game.resolve("securoguard");
        try (Stream<Path> s = Files.list(dir)) {
            assertTrue(s.noneMatch(p -> p.getFileName().toString().endsWith(".tmp")),
                    "atomic write must not leave .tmp files behind");
        }
    }

    @Test
    void corruptJsonIsPreservedAndThrows(@TempDir Path game) throws Exception {
        Path file = game.resolve("securoguard/baseline.json");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "{ this is not valid json", StandardCharsets.UTF_8);

        BaselineStore store = store(game);
        assertThrows(BaselineException.class, store::load);
        // The corrupt file must be preserved for review, not silently deleted.
        try (Stream<Path> s = Files.list(file.getParent())) {
            assertTrue(s.anyMatch(p -> p.getFileName().toString().contains(".corrupt-")),
                    "corrupt baseline should be moved aside with a .corrupt- suffix");
        }
    }

    @Test
    void unsupportedSchemaVersionThrows(@TempDir Path game) throws Exception {
        Path file = game.resolve("securoguard/baseline.json");
        Files.createDirectories(file.getParent());
        Files.writeString(file, "{\"schemaVersion\": 999, \"files\": []}", StandardCharsets.UTF_8);
        assertThrows(BaselineException.class, () -> store(game).load());
    }
}
