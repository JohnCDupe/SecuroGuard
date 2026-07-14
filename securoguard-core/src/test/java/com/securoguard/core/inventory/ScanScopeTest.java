package com.securoguard.core.inventory;

import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.instance.ScanScope;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R5: scoped scanning. The runtime scope must not touch worlds, logs, screenshots
 * etc.; limits must be enforced with skipped files reported.
 */
class ScanScopeTest {

    private InstancePaths instanceWithClutter(Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        write(paths.modsDir().resolve("a.jar"), "PKmodjar");
        write(game.resolve("config/mymod.json"), "{}");
        write(game.resolve("saves/world/level.dat"), "worlddata");
        write(game.resolve("logs/latest.log"), "log line");
        write(game.resolve("screenshots/pic.png"), "imgdata");
        write(game.resolve("crash-reports/crash.txt"), "boom");
        return paths;
    }

    private void write(Path p, String content) throws IOException {
        Files.createDirectories(p.getParent());
        Files.writeString(p, content, StandardCharsets.UTF_8);
    }

    private Set<String> relPaths(FileInventory inv) {
        return inv.records().stream().map(FileRecord::relativePath).collect(Collectors.toSet());
    }

    @Test
    void runtimeScopeCoversModsOnlyByDefault(@TempDir Path game) throws IOException {
        InstancePaths paths = instanceWithClutter(game);
        Set<String> rel = relPaths(new InventoryScanner(paths)
                .scanScoped(ScanScope.RUNTIME, List.of(), ScanLimits.defaults()).inventory());
        assertTrue(rel.contains("mods/a.jar"));
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("saves/")), "must not scan worlds");
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("logs/")), "must not scan logs");
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("screenshots/")));
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("config/")), "runtime excludes config by default");
    }

    @Test
    void prelaunchScopeAddsConfigButNotWorlds(@TempDir Path game) throws IOException {
        InstancePaths paths = instanceWithClutter(game);
        Set<String> rel = relPaths(new InventoryScanner(paths)
                .scanScoped(ScanScope.PRELAUNCH, List.of(), ScanLimits.defaults()).inventory());
        assertTrue(rel.contains("mods/a.jar"));
        assertTrue(rel.contains("config/mymod.json"));
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("saves/")));
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("logs/")));
    }

    @Test
    void fullScopeCoversEverythingButSecuroGuardData(@TempDir Path game) throws IOException {
        InstancePaths paths = instanceWithClutter(game);
        paths.createDataDirectories();
        Files.writeString(paths.dataDir().resolve("baseline-full.json"), "{}");
        Set<String> rel = relPaths(new InventoryScanner(paths)
                .scanScoped(ScanScope.FULL, List.of(), ScanLimits.defaults()).inventory());
        assertTrue(rel.contains("saves/world/level.dat"));
        assertTrue(rel.contains("logs/latest.log"));
        assertTrue(rel.stream().noneMatch(p -> p.startsWith("securoguard/")), "never scans its own data dir");
    }

    @Test
    void configuredMonitoredDirIsIncludedInRuntime(@TempDir Path game) throws IOException {
        InstancePaths paths = instanceWithClutter(game);
        write(game.resolve("extra/watched.bin"), "data");
        Path monitored = paths.resolveMonitoredDir("extra");
        assertNotNull(monitored);
        Set<String> rel = relPaths(new InventoryScanner(paths)
                .scanScoped(ScanScope.RUNTIME, List.of(monitored), ScanLimits.defaults()).inventory());
        assertTrue(rel.contains("extra/watched.bin"));
    }

    @Test
    void monitoredDirEscapingInstanceIsRejected(@TempDir Path game) {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        assertNull(paths.resolveMonitoredDir("../outside"));
        assertNull(paths.resolveMonitoredDir("/etc"));
        assertNotNull(paths.resolveMonitoredDir("mods"));
    }

    @Test
    void fileCountLimitTruncatesAndReports(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        for (int i = 0; i < 10; i++) {
            write(paths.modsDir().resolve("m" + i + ".jar"), "data" + i);
        }
        ScopedScan scan = new InventoryScanner(paths)
                .scanScoped(ScanScope.RUNTIME, List.of(), new ScanLimits(3, 512L * 1024 * 1024));
        assertTrue(scan.truncated(), "should truncate at the file-count limit");
        assertEquals(3, scan.inventory().size());
        assertFalse(scan.skipped().isEmpty(), "truncation must be reported, not silent");
    }

    @Test
    void oversizedFileIsSkippedAndReported(@TempDir Path game) throws IOException {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        write(paths.modsDir().resolve("small.jar"), "tiny");
        Files.write(paths.modsDir().resolve("big.jar"), new byte[5000]);
        ScopedScan scan = new InventoryScanner(paths)
                .scanScoped(ScanScope.RUNTIME, List.of(), new ScanLimits(200_000, 1000));
        Set<String> rel = relPaths(scan.inventory());
        assertTrue(rel.contains("mods/small.jar"));
        assertFalse(rel.contains("mods/big.jar"), "oversized file must not be hashed");
        assertTrue(scan.skipped().stream().anyMatch(s -> s.relativePath().equals("mods/big.jar")));
    }
}
