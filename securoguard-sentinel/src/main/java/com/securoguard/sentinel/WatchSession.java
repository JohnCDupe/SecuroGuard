package com.securoguard.sentinel;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.service.ScanReport;
import com.securoguard.core.service.ScanService;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The stateful core of {@code securoguard watch}, extracted so it can be driven
 * deterministically in tests without a real {@link com.securoguard.core.monitor.FilesystemMonitor}
 * or a blocking {@code Thread.join()}.
 *
 * <p>Behaviour (RB4):
 * <ul>
 *   <li>Alerts on findings at or above a configurable minimum severity (default HIGH),
 *       so a normal new untrusted JAR (HIGH) is not silently ignored.</li>
 *   <li>Tracks finding identities and prints only <em>newly raised or materially
 *       changed</em> findings — never the whole unchanged set after every event. A
 *       changed SHA-256 (carried in the evidence) is a new identity.</li>
 *   <li>Prints a concise resolution line when a previously-alerted finding disappears.</li>
 *   <li>Never claims which process or server caused a filesystem event.</li>
 * </ul>
 */
final class WatchSession {

    private final ScanService scanService;
    private final PrintStream out;
    private final InstancePaths paths;
    private final boolean redact;
    private final Severity minSeverity;

    /** Previously-alerted findings, keyed by a stable identity. */
    private final Map<String, Finding> reported = new LinkedHashMap<>();

    WatchSession(ScanService scanService, PrintStream out, InstancePaths paths,
                 boolean redact, Severity minSeverity) {
        this.scanService = scanService;
        this.out = out;
        this.paths = paths;
        this.redact = redact;
        this.minSeverity = minSeverity;
    }

    /** A stable identity: rule + path + evidence (evidence includes the hash). */
    static String keyOf(Finding f) {
        return f.ruleId() + "|" + f.affectedPath() + "|" + f.evidence();
    }

    /**
     * Runs a scan and prints only findings that are new or materially changed since
     * the last call, plus resolution lines for ones that disappeared. Returns the
     * number of newly-raised alerts (useful for tests). Never throws.
     */
    synchronized int onChange() {
        ScanReport report;
        try {
            report = scanService.scan(false, false);
        } catch (Exception e) {
            out.println("[watch] scan failed: " + e.getMessage());
            return 0;
        }
        Map<String, Finding> current = new LinkedHashMap<>();
        for (Finding f : report.findings()) {
            if (f.severity().compareTo(minSeverity) >= 0) {
                current.put(keyOf(f), f);
            }
        }
        int newlyRaised = 0;
        for (Map.Entry<String, Finding> e : current.entrySet()) {
            if (!reported.containsKey(e.getKey())) {
                printAlert(e.getValue());
                newlyRaised++;
            }
        }
        // Resolutions: previously reported, now gone.
        List<Finding> resolved = new ArrayList<>();
        for (Map.Entry<String, Finding> e : reported.entrySet()) {
            if (!current.containsKey(e.getKey())) {
                resolved.add(e.getValue());
            }
        }
        for (Finding f : resolved) {
            out.println("[resolved] " + f.ruleId()
                    + (f.affectedPath() != null ? " " + redactIfNeeded(f.affectedPath()) : ""));
        }
        reported.clear();
        reported.putAll(current);
        return newlyRaised;
    }

    private void printAlert(Finding f) {
        out.println("[ALERT " + f.severity() + "] " + f.ruleId() + " — " + f.title());
        if (f.affectedPath() != null) {
            out.println("      path: " + redactIfNeeded(f.affectedPath()));
        }
        if (f.evidence() != null && !f.evidence().isBlank()) {
            out.println("      evidence: " + redactIfNeeded(f.evidence()));
        }
        out.println("      recommended: " + f.recommendedAction()
                + "  (occurred during monitoring; SecuroGuard does not attribute the cause)");
    }

    private String redactIfNeeded(String text) {
        if (!redact || text == null) {
            return text;
        }
        return text.replace(paths.gameDir().toString(), "<instance>")
                .replace(System.getProperty("user.home", "~"), "<home>");
    }
}
