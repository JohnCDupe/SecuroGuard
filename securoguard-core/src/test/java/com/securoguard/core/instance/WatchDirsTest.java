package com.securoguard.core.instance;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * R6: the set of directories the runtime should watch — mods (mandatory) plus valid
 * configured directories, de-duplicated, escapes rejected, SecuroGuard's own data
 * directory never watched.
 */
class WatchDirsTest {

    @Test
    void modsIsAlwaysIncludedEvenWithNoConfig(@TempDir Path game) {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        LinkedHashSet<Path> dirs = paths.resolveWatchDirs(List.of());
        assertTrue(dirs.contains(paths.modsDir().toAbsolutePath().normalize()));
        assertEquals(1, dirs.size());
    }

    @Test
    void validConfiguredDirectoriesAreIncludedAndDeduplicated(@TempDir Path game) {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        LinkedHashSet<Path> dirs = paths.resolveWatchDirs(List.of("extra", "extra", "mods"));
        assertTrue(dirs.contains(paths.gameDir().resolve("extra")));
        assertTrue(dirs.contains(paths.modsDir().toAbsolutePath().normalize()));
        // "extra" appears once, "mods" collapses onto the mandatory entry.
        assertEquals(2, dirs.size());
    }

    @Test
    void escapingDirectoriesAreRejected(@TempDir Path game) {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        LinkedHashSet<Path> dirs = paths.resolveWatchDirs(List.of("../outside", "/etc", "C:\\win"));
        assertEquals(1, dirs.size(), "only mods remains; escaping paths are dropped");
    }

    @Test
    void securoguardDataDirectoryIsNeverWatched(@TempDir Path game) {
        InstancePaths paths = InstancePaths.ofGameDir(game);
        // securoguard, securoguard/quarantine and securoguard/logs must all be refused.
        LinkedHashSet<Path> dirs = paths.resolveWatchDirs(
                List.of("securoguard", "securoguard/quarantine", "securoguard/logs"));
        assertEquals(1, dirs.size(), "SecuroGuard's own data dirs must not be watched");
        assertFalse(dirs.stream().anyMatch(d -> d.startsWith(paths.dataDir())));
    }
}
