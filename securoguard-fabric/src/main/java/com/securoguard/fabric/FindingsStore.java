package com.securoguard.fabric;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.Severity;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Thread-safe holder for the latest findings and which ones the user has
 * dismissed. Dismissing a warning hides it from the alert surface but does NOT
 * grant the file any trust — that requires an explicit baseline approval elsewhere.
 */
public final class FindingsStore {

    private final Object lock = new Object();
    private List<Finding> current = List.of();
    private final Set<String> dismissed = new HashSet<>();

    public void replaceAll(List<Finding> findings) {
        synchronized (lock) {
            current = List.copyOf(findings);
        }
    }

    public List<Finding> all() {
        synchronized (lock) {
            return new ArrayList<>(current);
        }
    }

    /** Findings the user has not dismissed. */
    public List<Finding> active() {
        synchronized (lock) {
            List<Finding> out = new ArrayList<>();
            for (Finding f : current) {
                if (!dismissed.contains(key(f))) {
                    out.add(f);
                }
            }
            return out;
        }
    }

    public void dismiss(Finding f) {
        synchronized (lock) {
            dismissed.add(key(f));
        }
    }

    public Severity highestActiveSeverity() {
        Severity max = null;
        for (Finding f : active()) {
            if (max == null || f.severity().compareTo(max) > 0) {
                max = f.severity();
            }
        }
        return max;
    }

    public boolean hasActiveCritical() {
        return active().stream().anyMatch(f -> f.severity() == Severity.CRITICAL);
    }

    /**
     * A stable identity for dedupe/dismissal: rule + path + evidence. Because the
     * evidence carries the hash, a changed hash yields a new key — so a genuinely
     * new/altered file re-alerts rather than being silently coalesced.
     */
    public static String keyOf(Finding f) {
        return f.ruleId() + "|" + f.affectedPath() + "|" + f.evidence();
    }

    private static String key(Finding f) {
        return keyOf(f);
    }
}
