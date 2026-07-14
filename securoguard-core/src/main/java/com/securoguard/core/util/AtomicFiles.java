package com.securoguard.core.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Small helpers for writing files without leaving a half-written file behind if
 * the process dies mid-write. Used for the baseline, quarantine sidecars and
 * caches — anything where a torn write would corrupt trusted state.
 */
public final class AtomicFiles {

    private AtomicFiles() {
    }

    /**
     * Writes UTF-8 text to {@code target} atomically: content goes to a sibling
     * temp file which is then moved into place. When the platform cannot do an
     * atomic move (rare, e.g. across filesystems) we fall back to a plain move,
     * which is still better than writing {@code target} in place.
     */
    public static void writeString(Path target, String content) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        Path tmp = Files.createTempFile(dir, target.getFileName().toString(), ".tmp");
        try {
            Files.write(tmp, content.getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}
