package com.securoguard.core.inventory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An immutable, ordered set of {@link FileRecord}s keyed by instance-relative
 * path. Two inventories can be {@linkplain InventoryDiff diffed} to detect what
 * changed between a trusted baseline and a fresh scan.
 */
public final class FileInventory {

    private final Map<String, FileRecord> byRelativePath;

    private FileInventory(Map<String, FileRecord> records) {
        this.byRelativePath = Collections.unmodifiableMap(records);
    }

    public static FileInventory of(List<FileRecord> records) {
        Map<String, FileRecord> map = new LinkedHashMap<>();
        for (FileRecord r : records) {
            map.put(r.relativePath(), r);
        }
        return new FileInventory(map);
    }

    public static FileInventory empty() {
        return new FileInventory(new LinkedHashMap<>());
    }

    public FileRecord get(String relativePath) {
        return byRelativePath.get(relativePath);
    }

    public boolean contains(String relativePath) {
        return byRelativePath.containsKey(relativePath);
    }

    public List<FileRecord> records() {
        return new ArrayList<>(byRelativePath.values());
    }

    public int size() {
        return byRelativePath.size();
    }

    /** Live view of the relative-path -> record map (unmodifiable). */
    public Map<String, FileRecord> asMap() {
        return byRelativePath;
    }
}
