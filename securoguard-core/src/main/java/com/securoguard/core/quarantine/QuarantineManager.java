package com.securoguard.core.quarantine;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.instance.PathSecurity;
import com.securoguard.core.util.AtomicFiles;
import com.securoguard.core.util.Hashing;
import com.securoguard.core.util.Json;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Opt-in quarantine. Moves a suspicious file out of the instance into the
 * SecuroGuard quarantine directory and records what/why in a sidecar. Everything
 * here is fail-safe and reversible:
 *
 * <ul>
 *   <li><b>Never deletes automatically.</b> The only deletion is of the original
 *       <em>after</em> its quarantined copy is verified by hash.</li>
 *   <li><b>Verified copy-and-delete fallback.</b> If an atomic move is unavailable
 *       we copy, re-hash the destination, and only then remove the source.</li>
 *   <li><b>Not loadable.</b> Quarantined files live outside {@code mods/} and are
 *       stored with a {@code .quarantined} suffix, so the game can never load them
 *       even if the quarantine directory were misconfigured onto the classpath.</li>
 *   <li><b>Traversal-safe naming.</b> Only the basename is used for the stored
 *       name; destination collisions are avoided with a unique id.</li>
 * </ul>
 */
public final class QuarantineManager {

    private static final String SUFFIX = ".quarantined";
    private static final String SIDECAR_SUFFIX = ".json";
    private static final String FAILURE_SUFFIX = ".failed.json";
    private static final String PREPARED_SUFFIX = ".prepared.json";
    private static final Pattern SHA256_HEX = Pattern.compile("^[0-9a-f]{64}$");
    private static final Pattern ID_PATTERN = Pattern.compile("^[A-Za-z0-9._-]+$");

    /** Injectable hashing so tests can deterministically simulate a post-move mismatch. */
    @FunctionalInterface
    public interface Hasher {
        String hash(Path path) throws IOException;
    }

    private final Path quarantineDir;
    private final Path gameDir;
    private final Hasher hasher;

    public QuarantineManager(InstancePaths paths) {
        this(paths, Hashing::sha256);
    }

    QuarantineManager(InstancePaths paths, Hasher hasher) {
        this.quarantineDir = paths.quarantineDir().toAbsolutePath().normalize();
        this.gameDir = paths.gameDir().toAbsolutePath().normalize();
        this.hasher = hasher;
    }

    /**
     * Quarantines {@code file}, recording {@code triggeringFindings} in the sidecar.
     *
     * @throws QuarantineException if the file is outside the instance, cannot be
     *                             verified after the move, or any step fails
     */
    public QuarantineItem quarantine(Path file, List<Finding> triggeringFindings) throws QuarantineException {
        Path source = file.toAbsolutePath().normalize();
        try {
            // Refuse a symlink/junction source (NOFOLLOW) rather than hashing/moving
            // through it to a target that may live outside the instance.
            if (Files.isSymbolicLink(source) || PathSecurity.isLinkOrRedirect(source)) {
                throw new QuarantineException("Refusing to quarantine a symbolic link / junction: " + source);
            }
            if (!Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS)) {
                throw new QuarantineException("Not a regular file: " + source);
            }
            // Containment: refuse to quarantine anything outside the instance. This
            // prevents a crafted finding/path from moving arbitrary system files.
            if (!PathSecurity.isContained(gameDir, source)) {
                throw new QuarantineException("Refusing to quarantine a file outside the instance: " + source);
            }

            Files.createDirectories(quarantineDir);
            String sourceHash = hasher.hash(source);
            long size = Files.size(source);
            String id = generateId(sourceHash);
            String storedName = id + "__" + sanitize(source.getFileName().toString()) + SUFFIX;
            Path dest = quarantineDir.resolve(storedName).normalize();
            // Defence in depth: the resolved destination must stay inside quarantine.
            if (!dest.startsWith(quarantineDir)) {
                throw new QuarantineException("Computed quarantine path escaped the quarantine directory");
            }
            if (Files.exists(dest)) {
                throw new QuarantineException("Quarantine destination already exists: " + dest);
            }

            String relSource = relative(source);
            // 1. Durable PREPARED record BEFORE the move. If we cannot write it, we
            //    abort WITHOUT touching the source (no orphan can result).
            QuarantineTransaction prepared = new QuarantineTransaction(
                    QuarantineTransaction.SCHEMA_VERSION, id, relSource, storedName, sourceHash, size,
                    Instant.now().toEpochMilli());
            try {
                writePrepared(prepared);
            } catch (IOException e) {
                throw new QuarantineException("Could not write quarantine transaction record; source untouched", e);
            }

            // 2. Move the source in. A copy-path failure rolls back (source preserved,
            //    dest removed) — there is no orphan, so we clear the PREPARED record.
            try {
                moveInto(source, dest, sourceHash);
            } catch (QuarantineException moveFailed) {
                deletePrepared(storedName);
                throw moveFailed;
            }

            // 3. From here the source has moved; the stored file is the only copy. Any
            //    failure leaves the PREPARED record (and, where possible, a FAILED
            //    record) so listFailures() finds the orphan. Never delete it, never
            //    return it to mods.
            String finalHash;
            try {
                finalHash = hasher.hash(dest);
            } catch (IOException hashEx) {
                writeFailureQuietly(id, relSource, storedName, dest, sourceHash, null, "post-move-hash-io");
                throw new QuarantineException("Could not hash the quarantined file after the move; it was "
                        + "preserved as a recoverable orphan (see listFailures) and NOT returned to mods.", hashEx);
            }
            if (!sourceHash.equals(finalHash)) {
                writeFailureQuietly(id, relSource, storedName, dest, sourceHash, finalHash, "post-move-verify");
                throw new QuarantineException("Quarantined file failed post-move verification; preserved as a "
                        + "recoverable orphan and NOT returned to mods. dest=" + dest);
            }

            QuarantineItem item = new QuarantineItem(
                    QuarantineItem.SCHEMA_VERSION, id, source.toString(), relSource,
                    source.getFileName().toString(), storedName, sourceHash, size,
                    Instant.now().toEpochMilli(), summarise(triggeringFindings));
            try {
                writeSidecar(dest, item);
            } catch (IOException sidecarEx) {
                writeFailureQuietly(id, relSource, storedName, dest, sourceHash, finalHash, "sidecar-write");
                throw new QuarantineException("Quarantine sidecar could not be written after a verified move; "
                        + "the file was preserved as a recoverable orphan (see listFailures).", sidecarEx);
            }

            // 4. Success: finalize the transaction by removing the PREPARED record.
            deletePrepared(storedName);
            return item;
        } catch (IOException e) {
            throw new QuarantineException("I/O error during quarantine of " + source, e);
        }
    }

    // One-shot test seams to simulate durability failures at specific stages.
    private boolean failNextPreparedWrite;
    private boolean failNextSidecarWrite;

    void failNextPreparedWriteForTest() {
        failNextPreparedWrite = true;
    }

    void failNextSidecarWriteForTest() {
        failNextSidecarWrite = true;
    }

    private void writePrepared(QuarantineTransaction tx) throws IOException {
        if (failNextPreparedWrite) {
            failNextPreparedWrite = false;
            throw new IOException("simulated PREPARED-record write failure");
        }
        AtomicFiles.writeString(quarantineDir.resolve(tx.storedFileName() + PREPARED_SUFFIX),
                Json.gson().toJson(tx));
    }

    private void deletePrepared(String storedName) {
        try {
            Files.deleteIfExists(quarantineDir.resolve(storedName + PREPARED_SUFFIX));
        } catch (IOException ignored) {
            // A leftover PREPARED record is harmless: it only causes listFailures() to
            // surface an orphan that actually has a valid sidecar, which recovery ignores.
        }
    }

    /** Best-effort FAILED record; if even this write fails, the PREPARED record remains. */
    private void writeFailureQuietly(String id, String relSource, String storedName, Path dest,
                                     String expected, String observed, String stage) {
        try {
            QuarantineFailure failure = new QuarantineFailure(QuarantineFailure.SCHEMA_VERSION, id, relSource,
                    storedName, dest.toString(), expected, observed, Instant.now().toEpochMilli(), stage);
            writeFailureSidecar(dest, failure);
        } catch (IOException ignored) {
            // The durable PREPARED record already makes this orphan recoverable.
        }
    }

    /**
     * Moves the source into quarantine. Prefers an atomic move; on platforms that
     * cannot do it atomically (e.g. across filesystems) falls back to a
     * copy-verify-delete sequence so the original is only removed once the copy is
     * confirmed intact (that path never produces an orphan — a bad copy is rolled
     * back and the source is kept).
     *
     * @return true if the atomic move path was used
     */
    private boolean moveInto(Path source, Path dest, String expectedHash)
            throws IOException, QuarantineException {
        try {
            Files.move(source, dest, StandardCopyOption.ATOMIC_MOVE);
            return true;
        } catch (AtomicMoveNotSupportedException notAtomic) {
            Files.copy(source, dest, StandardCopyOption.COPY_ATTRIBUTES);
            String destHash = hasher.hash(dest);
            if (!expectedHash.equals(destHash)) {
                Files.deleteIfExists(dest); // roll back a bad copy; keep the original
                throw new QuarantineException("Quarantine copy failed hash verification; original preserved");
            }
            Files.delete(source); // safe: verified copy exists
            return false;
        }
    }

    private void writeFailureSidecar(Path dest, QuarantineFailure failure) throws IOException {
        Path sidecar = dest.resolveSibling(dest.getFileName() + FAILURE_SUFFIX);
        AtomicFiles.writeString(sidecar, Json.gson().toJson(failure));
    }

    /**
     * Lists orphaned quarantine objects that need manual recovery: files whose
     * post-move verification failed (FAILED records), plus any transaction that did
     * not finalize (a lingering PREPARED record whose stored file exists but has no
     * normal sidecar). The PREPARED path catches the case where even the FAILED
     * record could not be written. Results are de-duplicated by stored file name.
     */
    public List<QuarantineFailure> listFailures() throws IOException {
        List<QuarantineFailure> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        if (!Files.isDirectory(quarantineDir)) {
            return out;
        }
        // Explicit FAILED records first.
        try (var stream = Files.newDirectoryStream(quarantineDir, "*" + FAILURE_SUFFIX)) {
            for (Path sidecar : stream) {
                try {
                    QuarantineFailure f = Json.gson().fromJson(
                            Files.readString(sidecar, StandardCharsets.UTF_8), QuarantineFailure.class);
                    if (f != null && f.id() != null && f.storedFileName() != null && seen.add(f.storedFileName())) {
                        out.add(f);
                    }
                } catch (RuntimeException ignored) {
                    // a corrupt failure record must not break listing the rest
                }
            }
        }
        // Unfinalized transactions: PREPARED record present, stored file exists, but no
        // normal sidecar => the transaction did not complete => orphan.
        try (var stream = Files.newDirectoryStream(quarantineDir, "*" + PREPARED_SUFFIX)) {
            for (Path prep : stream) {
                try {
                    QuarantineTransaction tx = Json.gson().fromJson(
                            Files.readString(prep, StandardCharsets.UTF_8), QuarantineTransaction.class);
                    if (tx == null || tx.storedFileName() == null || seen.contains(tx.storedFileName())) {
                        continue;
                    }
                    Path stored = quarantineDir.resolve(tx.storedFileName());
                    Path normalSidecar = quarantineDir.resolve(tx.storedFileName() + SIDECAR_SUFFIX);
                    if (Files.exists(stored) && !Files.exists(normalSidecar)) {
                        seen.add(tx.storedFileName());
                        out.add(new QuarantineFailure(QuarantineFailure.SCHEMA_VERSION, tx.id(),
                                tx.originalRelativePath(), tx.storedFileName(), stored.toString(),
                                tx.expectedSha256(), null, tx.preparedAtMillis(), "incomplete-transaction"));
                    }
                } catch (RuntimeException ignored) {
                    // ignore a corrupt PREPARED record
                }
            }
        }
        return out;
    }

    /**
     * Restores a quarantined item to its original location, safely.
     *
     * <p>Security model — <b>no sidecar-controlled value can cause a write outside
     * the configured instance.</b> In particular {@code originalAbsolutePath} is
     * treated as untrusted display data and is <em>never</em> used as the target.
     * The target is reconstructed as {@code gameDir.resolve(validatedRelativePath)}.
     * The sidecar, the stored file, and the restore path are all validated before
     * a single byte is written, and the quarantine copy is preserved until the
     * restored file is verified.
     *
     * <p>Residual TOCTOU: the canonical parent/link checks and the copy are not one
     * atomic operation, so a sufficiently privileged local attacker who can swap a
     * parent directory for a symlink in the microseconds between the check and the
     * copy could still redirect it. Java NIO offers no fully atomic "create-only,
     * no-follow, contained" write across platforms; we minimise the window (canonical
     * checks immediately before a create-only copy) and document the residual risk.
     *
     * @throws QuarantineException on any validation failure; on failure the stored
     *                             quarantine file and its sidecar are left intact
     */
    public Path restore(String id, boolean confirmed) throws QuarantineException {
        if (!confirmed) {
            throw new QuarantineException("Restore requires explicit confirmation");
        }
        try {
            LoadedSidecar loaded = loadValidatedSidecar(id);
            QuarantineItem item = loaded.item;
            Path stored = loaded.storedFile;

            // 1. Stored-file integrity: size + content must match the sidecar. If not,
            //    the quarantine copy was tampered with — refuse and keep everything.
            if (Files.size(stored) != item.size()) {
                throw new QuarantineException("Stored quarantine file size does not match sidecar; refusing restore");
            }
            if (!item.sha256().equals(Hashing.sha256(stored))) {
                throw new QuarantineException("Stored quarantine file hash does not match sidecar; refusing restore");
            }

            // 2. Build the target from gameDir + the VALIDATED relative path only.
            Path target;
            try {
                target = PathSecurity.resolveContainedRelative(gameDir, item.originalRelativePath());
            } catch (SecurityException e) {
                throw new QuarantineException("Refusing unsafe restore target: " + e.getMessage());
            }

            // 3. The parent must already exist as a real (non-link) directory inside
            //    the instance, and nothing on the ancestor chain may redirect us out.
            Path parent = target.getParent();
            if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
                throw new QuarantineException("Restore target parent directory does not exist: " + item.originalRelativePath());
            }
            if (PathSecurity.hasRedirectedAncestor(gameDir, target)) {
                throw new QuarantineException("Restore target is redirected by a symlink/junction; refusing");
            }

            // 4. Never overwrite. The create-only copy below is the atomic guarantee;
            //    this NOFOLLOW pre-check just gives a clearer message.
            if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
                throw new QuarantineException("Refusing to overwrite existing restore target: " + item.originalRelativePath());
            }

            // 5. Copy-verify-delete. Files.copy WITHOUT REPLACE_EXISTING throws
            //    atomically if the target appeared, closing that TOCTOU window.
            try {
                Files.copy(stored, target);
            } catch (FileAlreadyExistsException e) {
                throw new QuarantineException("Refusing to overwrite existing restore target: " + item.originalRelativePath());
            }

            boolean verified;
            try {
                verified = Files.size(target) == item.size() && item.sha256().equals(Hashing.sha256(target));
            } catch (IOException e) {
                verified = false;
            }
            if (!verified) {
                Files.deleteIfExists(target); // roll back the bad copy; keep quarantine intact
                throw new QuarantineException("Restored file failed verification; quarantine copy and sidecar preserved");
            }

            // 6. Only now, with the restored file verified, remove the quarantine copy.
            Files.delete(stored);
            Files.deleteIfExists(loaded.sidecarFile);
            return target;
        } catch (IOException e) {
            throw new QuarantineException("I/O error during restore of " + id + " (quarantine copy preserved)", e);
        }
    }

    /**
     * Loads and structurally validates the sidecar for {@code id}. Every field that
     * could steer a filesystem operation is checked here so {@link #restore} can
     * assume a trustworthy descriptor. Throws rather than returning partial data.
     */
    private LoadedSidecar loadValidatedSidecar(String id) throws QuarantineException, IOException {
        if (id == null || id.isBlank() || !ID_PATTERN.matcher(id).matches()) {
            throw new QuarantineException("Invalid quarantine id");
        }
        if (!Files.isDirectory(quarantineDir)) {
            throw new QuarantineException("No quarantine directory; nothing to restore");
        }
        Path realQuarantine = quarantineDir.toRealPath();

        try (var stream = Files.newDirectoryStream(quarantineDir, "*" + SIDECAR_SUFFIX)) {
            for (Path sidecar : stream) {
                String sname = sidecar.getFileName().toString();
                if (sname.endsWith(FAILURE_SUFFIX) || sname.endsWith(PREPARED_SUFFIX)) {
                    continue; // failure / in-progress records are not restorable items
                }
                QuarantineItem item;
                try {
                    item = Json.gson().fromJson(Files.readString(sidecar, StandardCharsets.UTF_8), QuarantineItem.class);
                } catch (RuntimeException e) {
                    continue; // unparseable sidecar: skip, keep scanning for the requested id
                }
                if (item == null || item.id() == null || !id.equals(item.id())) {
                    continue;
                }
                // Found the requested id. From here, any problem is a hard failure.
                if (item.schemaVersion() != QuarantineItem.SCHEMA_VERSION) {
                    throw new QuarantineException("Unsupported quarantine sidecar schema version " + item.schemaVersion());
                }
                String stored = item.storedFileName();
                if (stored == null || !PathSecurity.isBasename(stored) || !stored.endsWith(SUFFIX)) {
                    throw new QuarantineException("Sidecar storedFileName is not a safe basename");
                }
                // storedFileName must be tied to this id, and the sidecar filename must match it.
                if (!stored.startsWith(id + "__")) {
                    throw new QuarantineException("Sidecar id/storedFileName mismatch");
                }
                if (!sidecar.getFileName().toString().equals(stored + SIDECAR_SUFFIX)) {
                    throw new QuarantineException("Sidecar filename does not match storedFileName");
                }
                if (item.sha256() == null || !SHA256_HEX.matcher(item.sha256()).matches()) {
                    throw new QuarantineException("Sidecar sha256 is not a valid 64-char lowercase hex hash");
                }
                if (item.size() < 0) {
                    throw new QuarantineException("Sidecar size is negative");
                }
                Path storedFile = quarantineDir.resolve(stored);
                // Never follow a link masquerading as a quarantined file.
                if (Files.isSymbolicLink(storedFile)) {
                    throw new QuarantineException("Stored quarantine object is a symbolic link; refusing");
                }
                if (!Files.isRegularFile(storedFile, LinkOption.NOFOLLOW_LINKS)) {
                    throw new QuarantineException("Stored quarantine file is missing or not a regular file");
                }
                // The stored object must be physically inside the real quarantine dir.
                if (!storedFile.toRealPath().startsWith(realQuarantine)) {
                    throw new QuarantineException("Stored quarantine file resolves outside the quarantine directory");
                }
                return new LoadedSidecar(item, storedFile, sidecar);
            }
        }
        throw new QuarantineException("No quarantined item with id " + id);
    }

    private record LoadedSidecar(QuarantineItem item, Path storedFile, Path sidecarFile) {
    }

    /** Lists all quarantined items by reading their sidecars. */
    public List<QuarantineItem> list() throws IOException {
        List<QuarantineItem> out = new ArrayList<>();
        if (!Files.isDirectory(quarantineDir)) {
            return out;
        }
        try (var stream = Files.newDirectoryStream(quarantineDir, "*" + SIDECAR_SUFFIX)) {
            for (Path sidecar : stream) {
                String sname = sidecar.getFileName().toString();
                if (sname.endsWith(FAILURE_SUFFIX) || sname.endsWith(PREPARED_SUFFIX)) {
                    continue; // failure / in-progress records are surfaced via listFailures()
                }
                try {
                    String json = Files.readString(sidecar, StandardCharsets.UTF_8);
                    QuarantineItem item = Json.gson().fromJson(json, QuarantineItem.class);
                    if (item != null && item.id() != null) {
                        out.add(item);
                    }
                } catch (RuntimeException ignored) {
                    // A corrupt sidecar should not break listing the rest.
                }
            }
        }
        return out;
    }

    public Optional<QuarantineItem> find(String id) throws IOException {
        for (QuarantineItem item : list()) {
            if (item.id().equals(id)) {
                return Optional.of(item);
            }
        }
        return Optional.empty();
    }

    private void writeSidecar(Path dest, QuarantineItem item) throws IOException {
        if (failNextSidecarWrite) {
            failNextSidecarWrite = false;
            throw new IOException("simulated sidecar write failure");
        }
        Path sidecar = dest.resolveSibling(dest.getFileName() + SIDECAR_SUFFIX);
        AtomicFiles.writeString(sidecar, Json.gson().toJson(item));
    }

    private List<QuarantineItem.TriggeringFinding> summarise(List<Finding> findings) {
        List<QuarantineItem.TriggeringFinding> out = new ArrayList<>();
        if (findings != null) {
            for (Finding f : findings) {
                out.add(new QuarantineItem.TriggeringFinding(f.ruleId(), f.severity().name(), f.title()));
            }
        }
        return out;
    }

    private String relative(Path source) {
        Path rel = gameDir.relativize(source);
        return rel.toString().replace('\\', '/');
    }

    private static String generateId(String sha256) {
        String shortHash = sha256.length() >= 12 ? sha256.substring(0, 12) : sha256;
        return System.currentTimeMillis() + "-" + shortHash;
    }

    /** Strips any path separators and control characters from a filename. */
    private static String sanitize(String name) {
        String base = name.replace('\\', '/');
        int slash = base.lastIndexOf('/');
        if (slash >= 0) {
            base = base.substring(slash + 1);
        }
        String cleaned = base.replaceAll("[^a-zA-Z0-9._-]", "_").toLowerCase(Locale.ROOT);
        return cleaned.isEmpty() ? "file" : cleaned;
    }
}
