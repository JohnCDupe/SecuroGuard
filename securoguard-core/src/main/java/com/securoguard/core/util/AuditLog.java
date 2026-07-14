package com.securoguard.core.util;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

/**
 * Minimal, dependency-free, size-bounded append log written under the SecuroGuard
 * data directory. Kept deliberately simple; the goal is an auditable trail of
 * security-relevant events, not a general logging framework.
 *
 * <p>Privacy: callers are responsible for not passing secrets. This class never
 * logs environment, headers or file contents on its own. When a single log file
 * exceeds {@code maxBytes} it is rotated to {@code <name>.1} (one generation),
 * bounding total disk use.
 */
public final class AuditLog {

    private final Path logFile;
    private final long maxBytes;
    private final Object lock = new Object();

    public AuditLog(Path logFile, long maxBytes) {
        this.logFile = logFile;
        this.maxBytes = maxBytes;
    }

    public void info(String message) {
        write("INFO", message);
    }

    public void warn(String message) {
        write("WARN", message);
    }

    public void error(String message) {
        write("ERROR", message);
    }

    private void write(String level, String message) {
        String line = Instant.now() + " [" + level + "] " + sanitize(message) + System.lineSeparator();
        synchronized (lock) {
            try {
                Files.createDirectories(logFile.getParent());
                rotateIfNeeded();
                Files.writeString(logFile, line, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                // Logging must never take down the caller; surface as unchecked only
                // if truly unexpected. Here we swallow to keep the app running, but
                // we do not hide it entirely from developers.
                throw new UncheckedIOException("Failed writing audit log", e);
            }
        }
    }

    private void rotateIfNeeded() throws IOException {
        if (Files.exists(logFile) && Files.size(logFile) > maxBytes) {
            Path rotated = logFile.resolveSibling(logFile.getFileName() + ".1");
            Files.move(logFile, rotated, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Strips CR/LF so a crafted message cannot forge extra log lines. */
    private static String sanitize(String message) {
        return message == null ? "" : message.replaceAll("[\\r\\n]+", " ").strip();
    }
}
