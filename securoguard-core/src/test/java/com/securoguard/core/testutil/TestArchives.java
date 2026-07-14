package com.securoguard.core.testutil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Helpers for building harmless archive fixtures in tests. Nothing here is or
 * resembles real malware; the "hostile" fixtures (zip bomb, traversal entry,
 * disguised extension) are only structurally interesting, never executable.
 */
public final class TestArchives {

    private TestArchives() {
    }

    /** Builds an in-memory JAR/ZIP from name -> bytes entries. */
    public static byte[] zipBytes(Map<String, byte[]> entries) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(out)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(e.getKey()));
                zip.write(e.getValue());
                zip.closeEntry();
            }
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
        return out.toByteArray();
    }

    /** A minimal, valid Fabric mod JAR with the given id/version. */
    public static byte[] fabricModJar(String modId, String version) {
        String fmj = """
                {
                  "schemaVersion": 1,
                  "id": "%s",
                  "version": "%s",
                  "name": "%s",
                  "environment": "*",
                  "entrypoints": { "client": ["com.example.Example"] }
                }
                """.formatted(modId, version, modId);
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("fabric.mod.json", fmj.getBytes(StandardCharsets.UTF_8));
        entries.put("com/example/Example.class", new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        return zipBytes(entries);
    }

    /** Writes bytes to a file and returns its path. */
    public static Path writeFile(Path dir, String name, byte[] bytes) throws IOException {
        Files.createDirectories(dir);
        Path p = dir.resolve(name);
        Files.write(p, bytes);
        return p;
    }

    /** A zip whose single entry decompresses to {@code uncompressedBytes} of zeros (high ratio). */
    public static byte[] compressibleZip(int uncompressedBytes) {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("payload.bin", new byte[uncompressedBytes]); // zeros compress enormously
        return zipBytes(entries);
    }

    /** A zip containing a directory-traversal entry name. Purely structural. */
    public static byte[] traversalZip() {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("../../evil.txt", "harmless".getBytes(StandardCharsets.UTF_8));
        entries.put("normal.txt", "ok".getBytes(StandardCharsets.UTF_8));
        return zipBytes(entries);
    }

    /** Wraps {@code inner} jar bytes as a nested jar entry inside a new jar {@code depth} times. */
    public static byte[] nestedJars(int depth) {
        byte[] current = fabricModJar("innermost", "1.0.0");
        for (int i = 0; i < depth; i++) {
            Map<String, byte[]> entries = new LinkedHashMap<>();
            entries.put("META-INF/jars/nested-" + i + ".jar", current);
            entries.put("marker-" + i + ".txt", ("level" + i).getBytes(StandardCharsets.UTF_8));
            current = zipBytes(entries);
        }
        return current;
    }
}
