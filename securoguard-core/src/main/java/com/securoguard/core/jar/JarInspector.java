package com.securoguard.core.jar;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.securoguard.core.instance.PathSecurity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

/**
 * Inspects a JAR/ZIP and extracts bounded metadata <em>without loading any
 * class, invoking any entrypoint, or deserializing any object</em>.
 *
 * <p>The inspector streams the archive with {@link ZipInputStream} and enforces
 * every {@link JarInspectionLimits} bound as it goes, so a zip bomb or a
 * pathological archive is turned into a finding rather than an OOM or a hang.
 * Nested JARs are recursed into (in memory, bounded) up to a depth limit.
 *
 * <p>All extraction is metadata-only. We never write archive contents to disk
 * using entry-supplied names, which is why entry names are validated by
 * {@link PathSecurity#isTraversalEntryName} and reported, never resolved.
 */
public final class JarInspector {

    // File extensions that, when they appear immediately before a .jar/.zip,
    // strongly suggest a disguise (e.g. "cool_schematic.litematic.jar").
    private static final Set<String> DISGUISE_EXTENSIONS = Set.of(
            "litematic", "schematic", "schem", "nbt",
            "png", "jpg", "jpeg", "gif", "webp",
            "txt", "json", "cfg", "properties",
            "exe", "scr", "bat", "cmd", "ps1", "js", "vbs", "dll");

    private final JarInspectionLimits limits;

    public JarInspector() {
        this(JarInspectionLimits.defaults());
    }

    public JarInspector(JarInspectionLimits limits) {
        this.limits = limits;
    }

    /**
     * Inspects the file at {@code path}. Never throws for a bad archive; problems
     * are captured on the result. May throw {@link IOException} only if the file
     * cannot be read at all.
     */
    public JarInspectionResult inspect(Path path) throws IOException {
        JarInspectionResult result = new JarInspectionResult();
        result.setDoubleExtension(hasDisguisedDoubleExtension(path.getFileName().toString()));

        long fileSize = Files.size(path);
        if (fileSize > limits.maxArchiveBytes()) {
            result.setLimitExceeded(true);
            result.addProblem("Archive exceeds max inspectable size (" + fileSize + " bytes)");
            return result;
        }

        byte[] bytes = Files.readAllBytes(path);
        long deadline = System.nanoTime() + limits.maxInspectionMillis() * 1_000_000L;
        inspectBytes(bytes, fileSize, 0, deadline, result);
        return result;
    }

    /** Inspects raw archive bytes (used for the top level and for nested JARs). */
    private void inspectBytes(byte[] archive, long compressedSize, int depth, long deadline,
                              JarInspectionResult result) {
        if (depth > result.maxNestedDepthSeen()) {
            result.setMaxNestedDepthSeen(depth);
        }
        // ZipInputStream silently yields zero entries for non-ZIP bytes instead of
        // erroring, so we validate the local-file/empty-archive magic ourselves.
        // "PK\3\4" = local file header, "PK\5\6" = empty archive end-of-central-dir.
        if (!hasZipMagic(archive)) {
            result.addMalformed("Not a ZIP/JAR archive (missing PK signature)");
            return;
        }
        // Bytes decompressed at THIS archive level only — used for a per-archive
        // compression-ratio check so a benign outer jar is not blamed for a nested
        // bomb (and vice versa). The global budget uses result.totalUncompressedBytes.
        long levelUncompressed = 0;
        boolean cleanEof = false;
        List<byte[]> nestedToRecurse = new ArrayList<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(archive))) {
            while (true) {
                ZipEntry entry;
                try {
                    entry = zip.getNextEntry();
                } catch (IOException | IllegalArgumentException e) {
                    // A failed getNextEntry means the archive is malformed (or uses an
                    // unsupported feature). We must NOT then mark it structurally valid.
                    categorizeArchiveError(e, result);
                    break;
                }
                if (entry == null) {
                    cleanEof = true;
                    break;
                }
                if (System.nanoTime() > deadline) {
                    tripLimit(result, "Inspection time budget exceeded");
                    break;
                }
                if (result.entryCount() >= limits.maxEntryCount()) {
                    tripLimit(result, "Entry count limit reached (" + limits.maxEntryCount() + ")");
                    break;
                }
                result.setEntryCount(result.entryCount() + 1);

                String name = entry.getName();
                if (PathSecurity.isTraversalEntryName(name)) {
                    result.addTraversalEntry(name); // report — never resolve
                }
                classifyEntryName(name, result);

                if (entry.isDirectory()) {
                    zip.closeEntry();
                    continue;
                }

                boolean wantMetadata = isFabricModJson(name) || isManifest(name);
                boolean wantNested = depth < limits.maxNestedDepth() && isJarName(name);

                long produced;
                if (wantMetadata || wantNested) {
                    byte[] content = readEntryBounded(zip, result, deadline);
                    if (content == null) {
                        break; // a limit / read error tripped; already recorded
                    }
                    produced = content.length;
                    if (isFabricModJson(name)) {
                        parseFabricModJson(content, result);
                    } else if (isManifest(name)) {
                        parseManifest(content, result);
                    }
                    if (wantNested) {
                        // Enforce the cumulative in-memory budget across all nested archives.
                        if (result.cumulativeArchiveBytes() + content.length > limits.maxTotalArchiveBytes()) {
                            tripLimit(result, "Cumulative nested-archive memory budget exceeded");
                            break;
                        }
                        result.addCumulativeArchiveBytes(content.length);
                        nestedToRecurse.add(content);
                    }
                } else {
                    produced = drainEntryBounded(zip, result, deadline);
                    if (produced < 0) {
                        break; // limit / read error tripped
                    }
                }

                levelUncompressed += produced;
                result.setTotalUncompressedBytes(result.totalUncompressedBytes() + produced);
                if (result.totalUncompressedBytes() > limits.maxUncompressedBytes()) {
                    tripLimit(result, "Total uncompressed size limit reached");
                    break;
                }
                zip.closeEntry();
            }
        } catch (ZipException e) {
            categorizeArchiveError(e, result);
        } catch (IOException e) {
            result.addMalformed("I/O error while inspecting archive: " + e.getMessage());
        }

        // Structural validity is only asserted on a clean end-of-stream, i.e. every
        // entry parsed without error. A limit trip or read failure leaves it false.
        if (cleanEof && !result.limitExceeded()) {
            result.setStructurallyValidZip(true);
        }

        // Per-archive compression-ratio check (zip-bomb heuristic).
        if (compressedSize > 0) {
            long ratio = levelUncompressed / compressedSize;
            if (ratio > limits.maxCompressionRatio()) {
                tripLimit(result, "Compression ratio " + ratio + " exceeds limit "
                        + limits.maxCompressionRatio() + " (depth " + depth + ")");
            }
        }

        // Validate fabric.mod.json nested-jar declarations against the real entries,
        // but only for the top-level jar (whose modMetadata we parsed here).
        if (depth == 0) {
            validateDeclaredNestedJars(result);
        }

        // Recurse into nested jars (depth-first, bounded by depth/time/memory).
        for (byte[] nested : nestedToRecurse) {
            if (System.nanoTime() > deadline) {
                tripLimit(result, "Inspection time budget exceeded before nested-jar recursion");
                return;
            }
            inspectBytes(nested, nested.length, depth + 1, deadline, result);
        }
    }

    /** Classifies a ZIP-parsing exception as an unsupported feature or malformed archive. */
    private static void categorizeArchiveError(Exception e, JarInspectionResult result) {
        String msg = e.getMessage() == null ? e.toString() : e.getMessage();
        String lower = msg.toLowerCase(Locale.ROOT);
        if (lower.contains("encrypt")) {
            result.addUnsupported("Encrypted ZIP entry (not inspected): " + msg);
        } else {
            result.addMalformed("Malformed archive: " + msg);
        }
    }

    private static void tripLimit(JarInspectionResult result, String message) {
        result.setLimitExceeded(true);
        result.addProblem(message);
    }

    /**
     * Cross-checks the {@code jars} array declared in fabric.mod.json against the
     * archive's real entries. A declared nested jar that is absent, or a declared
     * path that attempts traversal, is a discrepancy worth surfacing.
     */
    private void validateDeclaredNestedJars(JarInspectionResult result) {
        result.modMetadata().ifPresent(meta -> {
            for (String declared : meta.declaredNestedJars()) {
                if (declared == null || declared.isBlank()) {
                    continue;
                }
                if (PathSecurity.isTraversalEntryName(declared)) {
                    result.addTraversalEntry(declared);
                    continue;
                }
                boolean present = result.nestedJarEntries().stream().anyMatch(declared::equals);
                if (!present) {
                    result.addProblem("Declared nested jar not present in archive: " + declared);
                }
            }
        });
    }

    /** Reads a full entry into memory, bounded by per-entry, global and time limits. */
    private byte[] readEntryBounded(ZipInputStream zip, JarInspectionResult result, long deadline) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[16 * 1024];
        int n;
        try {
            while ((n = zip.read(buf)) != -1) {
                out.write(buf, 0, n);
                // Enforce the wall-clock budget mid-entry, not only between entries,
                // so a single huge entry cannot stall inspection indefinitely.
                if (System.nanoTime() > deadline) {
                    tripLimit(result, "Inspection time budget exceeded while reading an entry");
                    return null;
                }
                if (out.size() > limits.maxMetadataBytes()) {
                    tripLimit(result, "Metadata/nested entry exceeds per-entry limit");
                    return null;
                }
                if (result.totalUncompressedBytes() + out.size() > limits.maxUncompressedBytes()) {
                    tripLimit(result, "Total uncompressed size limit reached");
                    return null;
                }
            }
        } catch (IOException e) {
            result.addMalformed("I/O error reading entry: " + e.getMessage());
            return null;
        }
        return out.toByteArray();
    }

    /** Reads and discards an entry's bytes, returning the count, or -1 if a limit tripped. */
    private long drainEntryBounded(ZipInputStream zip, JarInspectionResult result, long deadline) {
        byte[] buf = new byte[64 * 1024];
        long total = 0;
        int n;
        try {
            while ((n = zip.read(buf)) != -1) {
                total += n;
                if (System.nanoTime() > deadline) {
                    tripLimit(result, "Inspection time budget exceeded while reading an entry");
                    return -1;
                }
                if (result.totalUncompressedBytes() + total > limits.maxUncompressedBytes()) {
                    tripLimit(result, "Total uncompressed size limit reached");
                    return -1;
                }
            }
        } catch (IOException e) {
            result.addMalformed("I/O error draining entry: " + e.getMessage());
            return -1;
        }
        return total;
    }

    private void classifyEntryName(String name, JarInspectionResult result) {
        String lower = name.toLowerCase(Locale.ROOT);
        if (lower.startsWith("meta-inf/") &&
                (lower.endsWith(".sf") || lower.endsWith(".rsa") || lower.endsWith(".dsa") || lower.endsWith(".ec"))) {
            result.setHasSignatureEntries(true);
        }
        if (isJarName(name) && !result.nestedJarEntries().contains(name)) {
            result.nestedJarEntries().add(name);
        }
    }

    private void parseFabricModJson(byte[] content, JarInspectionResult result) {
        try {
            JsonElement root = JsonParser.parseString(new String(content, StandardCharsets.UTF_8));
            if (!root.isJsonObject()) {
                result.addProblem("fabric.mod.json is not a JSON object");
                return;
            }
            JsonObject obj = root.getAsJsonObject();
            String id = optString(obj, "id");
            String name = optString(obj, "name");
            String version = optString(obj, "version");
            List<String> entrypoints = new ArrayList<>();
            if (obj.has("entrypoints") && obj.get("entrypoints").isJsonObject()) {
                for (var e : obj.getAsJsonObject("entrypoints").entrySet()) {
                    entrypoints.add(e.getKey());
                }
            }
            List<String> jars = new ArrayList<>();
            if (obj.has("jars") && obj.get("jars").isJsonArray()) {
                JsonArray arr = obj.getAsJsonArray("jars");
                for (JsonElement el : arr) {
                    if (el.isJsonObject() && el.getAsJsonObject().has("file")) {
                        jars.add(el.getAsJsonObject().get("file").getAsString());
                    }
                }
            }
            result.setModMetadata(new ModMetadata(id, name, version, entrypoints, jars));
        } catch (RuntimeException e) {
            result.addProblem("Unparseable fabric.mod.json: " + e.getMessage());
        }
    }

    private void parseManifest(byte[] content, JarInspectionResult result) {
        try {
            var manifest = new java.util.jar.Manifest(new ByteArrayInputStream(content));
            manifest.getMainAttributes().forEach((k, v) -> {
                String attr = k + ": " + v;
                if (attr.length() <= 256) {
                    result.manifestAttributes().add(attr);
                }
            });
        } catch (IOException e) {
            result.addProblem("Unparseable MANIFEST.MF: " + e.getMessage());
        }
    }

    // --- name helpers ---

    /** True if the bytes begin with a ZIP local-file, empty-archive or spanned signature. */
    private static boolean hasZipMagic(byte[] b) {
        if (b.length < 4 || b[0] != 0x50 || b[1] != 0x4B) {
            return false;
        }
        // PK\3\4 (local file), PK\5\6 (empty archive), PK\7\8 (spanned).
        return (b[2] == 0x03 && b[3] == 0x04)
                || (b[2] == 0x05 && b[3] == 0x06)
                || (b[2] == 0x07 && b[3] == 0x08);
    }

    private static boolean isFabricModJson(String name) {
        return name.equals("fabric.mod.json");
    }

    private static boolean isManifest(String name) {
        return name.equalsIgnoreCase("META-INF/MANIFEST.MF");
    }

    private static boolean isJarName(String name) {
        return name.toLowerCase(Locale.ROOT).endsWith(".jar");
    }

    private static String optString(JsonObject obj, String key) {
        return (obj.has(key) && obj.get(key).isJsonPrimitive()) ? obj.get(key).getAsString() : null;
    }

    /**
     * Detects a disguised double extension such as {@code map.litematic.jar}.
     * Public + static so it is directly unit-testable.
     */
    public static boolean hasDisguisedDoubleExtension(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        if (!lower.endsWith(".jar") && !lower.endsWith(".zip")) {
            return false;
        }
        String withoutArchive = lower.substring(0, lower.length() - 4);
        int dot = withoutArchive.lastIndexOf('.');
        if (dot < 0) {
            return false;
        }
        String penultimate = withoutArchive.substring(dot + 1);
        return DISGUISE_EXTENSIONS.contains(penultimate);
    }
}
