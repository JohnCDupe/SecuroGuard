package com.securoguard.core.service;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.inventory.DiffResult;
import com.securoguard.core.inventory.FileInventory;
import com.securoguard.core.inventory.ScopedScan;

import java.util.List;

/**
 * The result of a scan: the scope used, what changed versus the trusted baseline,
 * the findings, the freshly captured inventory (which can be promoted to a new
 * baseline via an explicit approval), and any files that were skipped.
 */
public record ScanReport(
        ScanScope scope,
        boolean baselineExisted,
        DiffResult diff,
        List<Finding> findings,
        FileInventory currentInventory,
        List<ScopedScan.Skipped> skipped,
        boolean truncated) {

    /** Highest severity among the findings, or null if there are none. */
    public Severity highestSeverity() {
        Severity max = null;
        for (Finding f : findings) {
            if (max == null || f.severity().compareTo(max) > 0) {
                max = f.severity();
            }
        }
        return max;
    }

    public long countAtLeast(Severity threshold) {
        return findings.stream().filter(f -> f.severity().compareTo(threshold) >= 0).count();
    }
}
