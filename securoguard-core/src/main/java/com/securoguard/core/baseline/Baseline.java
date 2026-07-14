package com.securoguard.core.baseline;

import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.inventory.FileInventory;

import java.time.Instant;

/**
 * The trusted set of files SecuroGuard has explicitly approved for an instance,
 * plus provenance metadata. A baseline is only ever created or replaced by an
 * explicit approval; discovering a new file never mutates it.
 *
 * <p>A baseline records the {@link ScanScope} it was captured with, because each
 * scope covers a different set of files — a runtime baseline (mods only) must not
 * be diffed against a full-instance scan.
 */
public final class Baseline {

    /**
     * Bumped when the on-disk JSON shape changes incompatibly. v2 added the scan
     * scope; v1 baselines are rejected on load with a re-approve message.
     */
    public static final int CURRENT_SCHEMA_VERSION = 2;

    private final int schemaVersion;
    private final ScanScope scope;
    private final Instant createdAt;
    private final Instant updatedAt;
    private final FileInventory inventory;

    public Baseline(int schemaVersion, ScanScope scope, Instant createdAt, Instant updatedAt,
                    FileInventory inventory) {
        this.schemaVersion = schemaVersion;
        this.scope = scope;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.inventory = inventory;
    }

    /** Creates a brand-new baseline from an approved inventory captured at {@code scope}. */
    public static Baseline create(FileInventory inventory, ScanScope scope) {
        Instant now = Instant.now();
        return new Baseline(CURRENT_SCHEMA_VERSION, scope, now, now, inventory);
    }

    /** Returns a new baseline with the same creation time/scope but refreshed contents. */
    public Baseline replaceInventory(FileInventory newInventory) {
        return new Baseline(CURRENT_SCHEMA_VERSION, scope, createdAt, Instant.now(), newInventory);
    }

    public int schemaVersion() {
        return schemaVersion;
    }

    public ScanScope scope() {
        return scope;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public Instant updatedAt() {
        return updatedAt;
    }

    public FileInventory inventory() {
        return inventory;
    }
}
