package com.securoguard.core.inventory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Best-effort file classification using both the filename extension and the
 * leading magic bytes. Signature detection is intentionally conservative: we only
 * recognise a handful of formats relevant to mod instances. Anything else is
 * {@link #UNKNOWN}, which is a neutral classification, never an accusation.
 */
public enum FileType {
    /** ZIP-based archive (JAR, ZIP, many mod formats). */
    ZIP_ARCHIVE,
    /** Plain text / config-like content (no binary signature). */
    TEXT,
    /** A class file (unexpected loose in an instance; worth noting). */
    JAVA_CLASS,
    /** Recognised as binary but not one of the above. */
    BINARY,
    /** Could not be determined. Neutral — not suspicious by itself. */
    UNKNOWN;

    // Magic numbers we care about.
    private static final byte[] ZIP_MAGIC = {0x50, 0x4B, 0x03, 0x04}; // "PK\3\4"
    private static final byte[] ZIP_EMPTY = {0x50, 0x4B, 0x05, 0x06}; // empty archive
    private static final byte[] CLASS_MAGIC = {(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE};

    /**
     * Classifies a file by reading a small header. Never loads or executes
     * content; reads at most a few bytes.
     */
    public static FileType detect(Path file) {
        byte[] header = new byte[8];
        int read = 0;
        try (InputStream in = Files.newInputStream(file)) {
            int n;
            while (read < header.length && (n = in.read(header, read, header.length - read)) != -1) {
                read += n;
            }
        } catch (IOException e) {
            return UNKNOWN;
        }

        return detectFromHeader(header, read);
    }

    /**
     * Classifies from already-read header bytes. Lets a caller read a file once and
     * both hash it and classify it, avoiding a second open (an efficiency fix).
     *
     * @param header buffer holding the first bytes of the file
     * @param len    number of valid bytes in {@code header}
     */
    public static FileType detectFromHeader(byte[] header, int len) {
        if (startsWith(header, len, ZIP_MAGIC) || startsWith(header, len, ZIP_EMPTY)) {
            return ZIP_ARCHIVE;
        }
        if (startsWith(header, len, CLASS_MAGIC)) {
            return JAVA_CLASS;
        }
        if (len == 0) {
            return UNKNOWN;
        }
        return looksTextual(header, len) ? TEXT : BINARY;
    }

    /**
     * The classification implied purely by the filename extension, used to detect
     * mismatches between claimed and actual type (e.g. a {@code .jar} that is not a
     * ZIP, or a {@code .png} that is actually a JAR).
     */
    public static FileType byExtension(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (lower.endsWith(".jar") || lower.endsWith(".zip")) {
            return ZIP_ARCHIVE;
        }
        if (lower.endsWith(".class")) {
            return JAVA_CLASS;
        }
        if (lower.endsWith(".json") || lower.endsWith(".txt") || lower.endsWith(".toml")
                || lower.endsWith(".properties") || lower.endsWith(".cfg")) {
            return TEXT;
        }
        return UNKNOWN;
    }

    private static boolean startsWith(byte[] buf, int len, byte[] prefix) {
        if (len < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (buf[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean looksTextual(byte[] buf, int len) {
        for (int i = 0; i < len; i++) {
            int b = buf[i] & 0xFF;
            // Control chars other than tab/newline/carriage-return/formfeed suggest binary.
            if (b < 0x09 || (b > 0x0D && b < 0x20)) {
                return false;
            }
        }
        return true;
    }
}
