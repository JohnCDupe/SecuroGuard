package com.securoguard.core.baseline;

import com.google.gson.JsonSyntaxException;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.inventory.FileInventory;
import com.securoguard.core.inventory.FileRecord;
import com.securoguard.core.inventory.FileType;
import com.securoguard.core.util.AtomicFiles;
import com.securoguard.core.util.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Reads and writes the trusted {@link Baseline} as documented JSON under the
 * SecuroGuard data directory.
 *
 * <p>Design decisions, each security-relevant:
 * <ul>
 *   <li><b>Documented text format, never Java serialization.</b> The on-disk shape
 *       is a small DTO ({@link StoredBaseline}) so it is auditable and cannot be
 *       used as a deserialization gadget.</li>
 *   <li><b>Absolute paths are not stored.</b> Only instance-relative paths are
 *       persisted; the absolute path is reconstructed from the current game
 *       directory on load. This keeps baselines portable and avoids baking a
 *       user's home directory into a file that might be shared in a bug report.</li>
 *   <li><b>Atomic writes.</b> A torn write must never leave the trusted baseline
 *       half-updated.</li>
 *   <li><b>Corrupt files are preserved, not overwritten.</b></li>
 * </ul>
 */
public final class BaselineStore {

    private final Path baselineFile;
    private final Path gameDir;

    public BaselineStore(Path baselineFile, Path gameDir) {
        this.baselineFile = baselineFile.toAbsolutePath().normalize();
        this.gameDir = gameDir.toAbsolutePath().normalize();
    }

    /**
     * Loads the baseline.
     *
     * @return empty if no baseline file exists yet
     * @throws BaselineException if the file exists but is corrupt or an unsupported
     *                           schema version; the bad file is renamed aside first
     */
    public Optional<Baseline> load() throws BaselineException, IOException {
        if (!Files.exists(baselineFile)) {
            return Optional.empty();
        }
        String json = Files.readString(baselineFile, StandardCharsets.UTF_8);
        StoredBaseline stored;
        try {
            stored = Json.gson().fromJson(json, StoredBaseline.class);
        } catch (JsonSyntaxException e) {
            preserveCorrupt();
            throw new BaselineException("Baseline JSON is not parseable; preserved for review", e);
        }
        if (stored == null || stored.files == null) {
            preserveCorrupt();
            throw new BaselineException("Baseline JSON is empty or missing 'files'; preserved for review");
        }
        if (stored.schemaVersion != Baseline.CURRENT_SCHEMA_VERSION) {
            preserveCorrupt();
            throw new BaselineException("Unsupported baseline schema version " + stored.schemaVersion
                    + " (expected " + Baseline.CURRENT_SCHEMA_VERSION + "). This baseline predates scan scopes; "
                    + "please re-approve to create a fresh baseline. The old file was preserved for review.");
        }
        ScanScope scope = ScanScope.fromId(stored.scope);
        if (scope == null) {
            preserveCorrupt();
            throw new BaselineException("Baseline is missing or has an unknown scan scope; preserved for review");
        }

        List<FileRecord> records = new ArrayList<>(stored.files.size());
        for (StoredFile f : stored.files) {
            if (f == null || f.relativePath == null || f.sha256 == null) {
                preserveCorrupt();
                throw new BaselineException("Baseline contains an incomplete file entry; preserved for review");
            }
            // Reconstruct the absolute path from the current game dir + relative path.
            Path abs = gameDir.resolve(f.relativePath).normalize();
            FileType type = parseType(f.detectedType);
            records.add(new FileRecord(
                    abs.toString(),
                    f.relativePath,
                    f.fileName != null ? f.fileName : abs.getFileName().toString(),
                    f.size,
                    f.lastModifiedMillis,
                    f.sha256,
                    type,
                    f.inModsDir,
                    f.loadedAsMod));
        }
        Baseline baseline = new Baseline(
                stored.schemaVersion,
                scope,
                Instant.ofEpochMilli(stored.createdAtMillis),
                Instant.ofEpochMilli(stored.updatedAtMillis),
                FileInventory.of(records));
        return Optional.of(baseline);
    }

    /** Persists the baseline atomically. */
    public void save(Baseline baseline) throws IOException {
        StoredBaseline stored = new StoredBaseline();
        stored.schemaVersion = baseline.schemaVersion();
        stored.scope = baseline.scope().id();
        stored.createdAtMillis = baseline.createdAt().toEpochMilli();
        stored.updatedAtMillis = baseline.updatedAt().toEpochMilli();
        stored.files = new ArrayList<>();
        for (FileRecord r : baseline.inventory().records()) {
            StoredFile f = new StoredFile();
            f.relativePath = r.relativePath();
            f.fileName = r.fileName();
            f.size = r.size();
            f.lastModifiedMillis = r.lastModifiedMillis();
            f.sha256 = r.sha256();
            f.detectedType = r.detectedType().name();
            f.inModsDir = r.inModsDir();
            f.loadedAsMod = r.loadedAsMod();
            stored.files.add(f);
        }
        AtomicFiles.writeString(baselineFile, Json.gson().toJson(stored));
    }

    private void preserveCorrupt() throws IOException {
        Path corrupt = baselineFile.resolveSibling(
                baselineFile.getFileName() + ".corrupt-" + System.currentTimeMillis());
        try {
            Files.move(baselineFile, corrupt, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            // If we cannot move it, copy so the original stays put for review.
            Files.copy(baselineFile, corrupt, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static FileType parseType(String name) {
        if (name == null) {
            return FileType.UNKNOWN;
        }
        try {
            return FileType.valueOf(name);
        } catch (IllegalArgumentException e) {
            return FileType.UNKNOWN;
        }
    }

    // --- On-disk DTOs (documented in docs/advisory-format.md is the feed; baseline
    // shape is documented in README). Kept package-private and dumb on purpose. ---

    static final class StoredBaseline {
        int schemaVersion;
        String scope;
        long createdAtMillis;
        long updatedAtMillis;
        List<StoredFile> files;
    }

    static final class StoredFile {
        String relativePath;
        String fileName;
        long size;
        long lastModifiedMillis;
        String sha256;
        String detectedType;
        boolean inModsDir;
        boolean loadedAsMod;
    }
}
