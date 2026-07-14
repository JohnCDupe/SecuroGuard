package com.securoguard.core.instance;

/**
 * How much of an instance a scan looks at. Scope keeps the hot runtime path cheap
 * (a JAR landing in {@code mods} must not trigger rehashing every world save and
 * log file) while still allowing a deliberate, slower forensic sweep.
 *
 * <p>Because each scope covers a different set of files, baselines are tracked
 * <em>per scope</em> — comparing a runtime scan against a full-instance baseline
 * would report spurious removals.
 */
public enum ScanScope {

    /**
     * Runtime security surface: the mods directory plus explicitly configured
     * monitored directories. Excludes worlds, logs, screenshots, crash reports,
     * resource/asset caches, etc.
     */
    RUNTIME("runtime"),

    /**
     * Pre-launch security surface: mods, config, and configured monitored
     * directories. A superset of {@link #RUNTIME}, still excluding bulk/volatile
     * data like worlds and logs.
     */
    PRELAUNCH("prelaunch"),

    /**
     * The entire instance directory (minus SecuroGuard's own data dir). Forensic
     * only, on explicit request — potentially slow on large instances.
     */
    FULL("full");

    private final String id;

    ScanScope(String id) {
        this.id = id;
    }

    /** Stable lowercase identifier used in filenames and the baseline schema. */
    public String id() {
        return id;
    }

    public static ScanScope fromId(String s) {
        if (s == null) {
            return null;
        }
        for (ScanScope scope : values()) {
            if (scope.id.equalsIgnoreCase(s.trim())) {
                return scope;
            }
        }
        return null;
    }
}
