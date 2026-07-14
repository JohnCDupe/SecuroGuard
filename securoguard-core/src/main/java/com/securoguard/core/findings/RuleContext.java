package com.securoguard.core.findings;

import com.securoguard.core.inventory.DiffResult;
import com.securoguard.core.inventory.InstalledMod;
import com.securoguard.core.jar.JarInspectionResult;
import com.securoguard.core.reputation.ReputationResult;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Everything the rules need, assembled by the scanning layer and handed to the
 * {@link RuleEngine}. Rules read this and emit {@link Finding}s; they do not
 * perform I/O or make UI decisions.
 *
 * <p>Session context ({@code sessionActive}, {@code connectedToServer}) is what
 * lets a "new JAR" be escalated to CRITICAL: a JAR appearing <em>while the game is
 * running</em> is far more alarming than one present at a cold scan. We record
 * "occurred while connected" without ever claiming the server caused it.
 */
public final class RuleContext {

    private final boolean sessionActive;
    private final boolean connectedToServer;
    private final DiffResult diff;
    private final Map<String, JarInspectionResult> inspectionsByRelPath;
    private final Set<String> knownMaliciousHashes;
    private final Map<String, ReputationResult> reputationBySha;
    private final Map<String, InstalledMod> loadedModByRelPath;
    private final boolean baselineExists;

    private RuleContext(Builder b) {
        this.sessionActive = b.sessionActive;
        this.connectedToServer = b.connectedToServer;
        this.diff = b.diff;
        this.inspectionsByRelPath = Collections.unmodifiableMap(b.inspectionsByRelPath);
        this.knownMaliciousHashes = Collections.unmodifiableSet(b.knownMaliciousHashes);
        this.reputationBySha = Collections.unmodifiableMap(b.reputationBySha);
        this.loadedModByRelPath = Collections.unmodifiableMap(b.loadedModByRelPath);
        this.baselineExists = b.baselineExists;
    }

    /**
     * Whether a trusted baseline exists. "New since baseline" rules only fire when
     * this is true — with no baseline there is nothing to be new relative to, so
     * flagging every installed file would be noise, not signal.
     */
    public boolean baselineExists() {
        return baselineExists;
    }

    public boolean sessionActive() {
        return sessionActive;
    }

    public boolean connectedToServer() {
        return connectedToServer;
    }

    public DiffResult diff() {
        return diff;
    }

    public JarInspectionResult inspectionFor(String relativePath) {
        return inspectionsByRelPath.get(relativePath);
    }

    public boolean isKnownMalicious(String sha256) {
        return knownMaliciousHashes.contains(sha256);
    }

    public ReputationResult reputationFor(String sha256) {
        return reputationBySha.get(sha256);
    }

    /** The loader-reported mod occupying this relative path, if any (for advisories). */
    public InstalledMod loadedModFor(String relativePath) {
        return loadedModByRelPath.get(relativePath);
    }

    public Map<String, InstalledMod> loadedMods() {
        return loadedModByRelPath;
    }

    public static Builder builder(DiffResult diff) {
        return new Builder(diff);
    }

    public static final class Builder {
        private final DiffResult diff;
        private boolean sessionActive;
        private boolean connectedToServer;
        private Map<String, JarInspectionResult> inspectionsByRelPath = new HashMap<>();
        private Set<String> knownMaliciousHashes = new HashSet<>();
        private Map<String, ReputationResult> reputationBySha = new HashMap<>();
        private Map<String, InstalledMod> loadedModByRelPath = new HashMap<>();
        private boolean baselineExists = true; // default: a RuleContext assumes baseline context

        private Builder(DiffResult diff) {
            this.diff = diff;
        }

        public Builder baselineExists(boolean v) {
            this.baselineExists = v;
            return this;
        }

        public Builder sessionActive(boolean v) {
            this.sessionActive = v;
            return this;
        }

        public Builder connectedToServer(boolean v) {
            this.connectedToServer = v;
            return this;
        }

        public Builder inspections(Map<String, JarInspectionResult> v) {
            this.inspectionsByRelPath = v;
            return this;
        }

        public Builder knownMaliciousHashes(Set<String> v) {
            this.knownMaliciousHashes = v;
            return this;
        }

        public Builder reputation(Map<String, ReputationResult> v) {
            this.reputationBySha = v;
            return this;
        }

        public Builder loadedMods(Map<String, InstalledMod> v) {
            this.loadedModByRelPath = v;
            return this;
        }

        public RuleContext build() {
            return new RuleContext(this);
        }
    }
}
