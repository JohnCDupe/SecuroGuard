package com.securoguard.fabric;

import com.securoguard.core.baseline.Baseline;
import com.securoguard.core.baseline.BaselineException;
import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.monitor.FilesystemMonitor;
import com.securoguard.core.monitor.MonitorListener;
import com.securoguard.core.quarantine.QuarantineException;
import com.securoguard.core.quarantine.QuarantineItem;
import com.securoguard.core.quarantine.QuarantineManager;
import com.securoguard.core.service.ScanReport;
import com.securoguard.core.service.ScanService;
import com.securoguard.core.service.SecuroGuardConfig;
import com.securoguard.core.util.AuditLog;

import net.minecraft.client.MinecraftClient;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.securoguard.core.monitor.MonitorHealth;

import java.nio.file.Path;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BiConsumer;

/**
 * Owns SecuroGuard's runtime state inside Minecraft and bridges it to the
 * loader-neutral core.
 *
 * <p>Threading contract: <em>no hashing, archive inspection or filesystem writes
 * ever happen on the render thread.</em> All scanning and quarantine work runs on
 * a dedicated single-thread executor (or the monitor's own scan thread); only
 * lightweight UI notifications hop back onto the client thread via
 * {@link MinecraftClient#execute}.
 */
public final class SecuroGuardRuntime implements AutoCloseable {

    private static final Logger LOG = LoggerFactory.getLogger("SecuroGuard");

    private final InstancePaths paths;
    private final SecuroGuardConfig config;
    private final ScanService scanService;
    private final QuarantineManager quarantineManager;
    private final SessionState session = new SessionState();
    private final FindingsStore findings = new FindingsStore();
    private final AuditLog auditLog;
    private final ExecutorService worker =
            Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "securoguard-runtime");
                t.setDaemon(true);
                return t;
            });

    // One monitor per watched directory (mods is mandatory). A failed optional
    // directory watcher never disables mods monitoring.
    private final Map<Path, FilesystemMonitor> monitors = new java.util.concurrent.ConcurrentHashMap<>();
    private volatile FilesystemMonitor modsMonitor;
    private volatile boolean baselinePresent;
    // Coalesces bursts of monitor events into a single pending rescan.
    private final AtomicBoolean rescanPending = new AtomicBoolean(false);
    // Critical findings we have already alerted on, so we do not spam the same one.
    private final Set<String> alertedCriticalKeys = Collections.synchronizedSet(new HashSet<>());

    public SecuroGuardRuntime(InstancePaths paths, SecuroGuardConfig config) {
        this.paths = paths;
        this.config = config;
        this.scanService = new ScanService(paths, RuleEngine.withDefaultRules(),
                null /* offline by default; runtime keeps the game responsive */,
                Set.copyOf(config.knownMaliciousHashes));
        this.quarantineManager = new QuarantineManager(paths);
        this.auditLog = new AuditLog(paths.logDir().resolve("securoguard.log"), 1024 * 1024);
    }

    public SessionState session() {
        return session;
    }

    public FindingsStore findings() {
        return findings;
    }

    public InstancePaths paths() {
        return paths;
    }

    public boolean isMonitoring() {
        FilesystemMonitor m = modsMonitor;
        return m != null && m.isRunning(); // mods monitoring is the mandatory signal
    }

    /**
     * Aggregate, human-readable monitor health across all watched directories:
     * "all active", "partially degraded" (some optional dir failed but mods is up),
     * or "runtime monitoring stopped" (mods monitor is not active).
     */
    public String monitorHealth() {
        FilesystemMonitor mods = modsMonitor;
        if (mods == null || !mods.isRunning()) {
            return "Runtime monitoring STOPPED";
        }
        int total = monitors.size();
        long active = monitors.values().stream()
                .filter(m -> m.health().state() == MonitorHealth.State.RUNNING).count();
        if (active == total) {
            return "All active (" + total + " director" + (total == 1 ? "y" : "ies") + ")";
        }
        return "Partially degraded (" + active + "/" + total + " directories fully active; mods active)";
    }

    public boolean baselinePresent() {
        return baselinePresent;
    }

    /** Runs the initial comparison off-thread and then starts the monitor. */
    public void startAsync() {
        auditLog.info("SecuroGuard starting for instance " + paths.gameDir());
        LOG.info("SecuroGuard: loaded {} mods; game dir {}",
                FabricModInventory.loadedModCount(), paths.gameDir());
        worker.execute(() -> {
            // Feed Fabric's authoritative loaded-mod inventory into the core so files
            // are correctly attributed as loaded mods and carry coordinates for advisories.
            scanService.withLoadedMods(FabricModInventory.loadedMods())
                    .withAdvisorySource(new com.securoguard.core.advisory.BundledAdvisorySource())
                    .withMinecraftVersion(FabricModInventory.minecraftVersion())
                    // Runtime uses the cheap RUNTIME scope: mods + configured dirs only,
                    // never rehashing worlds/logs on every JAR event.
                    .withDefaultScope(com.securoguard.core.instance.ScanScope.RUNTIME)
                    .withMonitoredDirectories(config.monitoredDirectories)
                    .withScanLimits(config.scanLimits());
            rescanInternal();
            startMonitor();
        });
    }

    private void startMonitor() {
        MonitorListener listener = new MonitorListener() {
            @Override
            public void onFileSettled(Path file) {
                scheduleRescan(); // coalesced; runs on the runtime worker, off the render thread
            }

            @Override
            public void onFileRemoved(Path file) {
                scheduleRescan();
            }

            @Override
            public void onReconciled(Set<Path> currentFiles) {
                // A reconciliation may have recovered missed changes; rescan (coalesced).
                scheduleRescan();
            }

            @Override
            public void onFailure(String message, Throwable cause, boolean fatal) {
                LOG.warn("SecuroGuard monitor {}: {}", fatal ? "FATAL" : "warning", message, cause);
                auditLog.warn("monitor " + (fatal ? "fatal" : "warning") + ": " + message);
                if (fatal) {
                    // Make a dead monitor unmistakable to the user, not silently "active".
                    MinecraftClient client = MinecraftClient.getInstance();
                    client.execute(() -> {
                        if (client.player != null) {
                            client.player.sendMessage(Text.literal(
                                    "[SecuroGuard] Monitoring stopped unexpectedly. Runtime protection is OFF "
                                            + "until you restart.").formatted(Formatting.RED), false);
                        }
                    });
                }
            }
        };
        // Watch mods (mandatory) plus every valid configured directory. Non-recursive.
        // A failed OPTIONAL watcher is logged but never disables mods monitoring.
        Path modsDir = paths.modsDir().toAbsolutePath().normalize();
        for (Path dir : paths.resolveWatchDirs(config.monitoredDirectories)) {
            try {
                FilesystemMonitor m = new FilesystemMonitor(dir, listener,
                        config.watchQuietPeriodMillis, 500, config.reconcileIntervalMillis,
                        System::currentTimeMillis);
                m.start();
                monitors.put(dir, m);
                if (dir.equals(modsDir)) {
                    this.modsMonitor = m;
                }
                auditLog.info("Monitoring directory: " + dir);
            } catch (Exception e) {
                if (dir.equals(modsDir)) {
                    LOG.error("SecuroGuard could not start the mandatory mods monitor", e);
                    auditLog.error("could not start mods monitor: " + e);
                } else {
                    LOG.warn("SecuroGuard could not start optional monitor for {} (mods monitoring continues)",
                            dir, e);
                    auditLog.warn("optional monitor failed for " + dir + ": " + e);
                }
            }
        }
    }

    /** Requests a re-scan (used by the /securoguard scan command and UI). Coalesced. */
    public void requestRescan() {
        scheduleRescan();
    }

    /**
     * Coalesces rescan requests: if one is already pending, further requests are
     * dropped until it starts, so a burst of monitor events produces a single scan
     * rather than one per event.
     */
    private void scheduleRescan() {
        if (rescanPending.compareAndSet(false, true)) {
            worker.execute(() -> {
                rescanPending.set(false);
                rescanInternal();
            });
        }
    }

    private void rescanInternal() {
        try {
            ScanReport report = scanService.scan(session.isSessionActive(), session.isConnectedToServer());
            this.baselinePresent = report.baselineExisted();
            List<Finding> before = findings.active();
            findings.replaceAll(report.findings());
            maybeWarnOnNewCritical(before, report.findings());
        } catch (BaselineException e) {
            LOG.warn("SecuroGuard baseline problem (treated as no trust): {}", e.getMessage());
            auditLog.warn("baseline problem: " + e.getMessage());
        } catch (Exception e) {
            LOG.error("SecuroGuard scan failed", e);
            auditLog.error("scan failed: " + e);
        }
    }

    /**
     * Alerts once per <em>distinct</em> new CRITICAL finding. A finding is keyed by
     * rule + path + evidence (which includes the hash), so a changed hash re-alerts
     * but the same finding never spams. Dismissing does not grant trust and does not
     * suppress a future alert for a genuinely different finding.
     */
    private void maybeWarnOnNewCritical(List<Finding> before, List<Finding> now) {
        List<Finding> newCriticals = now.stream()
                .filter(f -> f.severity() == Severity.CRITICAL)
                .filter(f -> alertedCriticalKeys.add(FindingsStore.keyOf(f))) // true only if not seen before
                .toList();
        if (newCriticals.isEmpty()) {
            return;
        }
        auditLog.warn("CRITICAL finding(s) raised during session: " + newCriticals.size());
        MinecraftClient client = MinecraftClient.getInstance();
        client.execute(() -> {
            if (client.player != null) {
                client.player.sendMessage(Text.translatable("securoguard.toast.critical.desc")
                        .formatted(Formatting.RED, Formatting.BOLD), false);
                client.player.sendMessage(Text.translatable("securoguard.warn.open_screen")
                        .formatted(Formatting.RED), false);
            }
        });
    }

    /** Whether the in-game quarantine action is enabled (config). Sentinel quarantine is separate. */
    public boolean quarantineEnabled() {
        return config.quarantineEnabled;
    }

    /**
     * Disconnects from the current multiplayer server using Minecraft's normal client
     * disconnect path. No-op in menus or single-player. Requires no server support and
     * does not assert the server caused any file event.
     */
    public void disconnectFromServer() {
        MinecraftClient client = MinecraftClient.getInstance();
        client.execute(() -> {
            var handler = client.getNetworkHandler();
            if (handler != null && !client.isIntegratedServerRunning()) {
                auditLog.info("user disconnected from server via SecuroGuard");
                handler.getConnection().disconnect(Text.translatable("securoguard.disconnect.reason"));
            }
        });
    }

    /**
     * Quarantines the file referenced by a finding. Runs off the render thread and
     * re-scans afterwards. Callers (UI) must have obtained explicit confirmation and
     * checked {@link #quarantineEnabled()}. The result (ok + message) is delivered on
     * the client thread so the UI can show success or failure.
     */
    public void quarantineAsync(Finding finding, BiConsumer<Boolean, String> onResult) {
        if (!config.quarantineEnabled) {
            deliver(onResult, false, "Quarantine is disabled in configuration");
            return;
        }
        if (finding.affectedPath() == null) {
            deliver(onResult, false, "Finding has no file to quarantine");
            return;
        }
        worker.execute(() -> {
            try {
                Path file = paths.gameDir().resolve(finding.affectedPath()).normalize();
                QuarantineItem item = quarantineManager.quarantine(file, List.of(finding));
                auditLog.warn("quarantined " + item.originalRelativePath() + " sha256=" + item.sha256());
                rescanInternal();
                deliver(onResult, true, "Quarantined " + item.originalRelativePath());
            } catch (QuarantineException e) {
                LOG.error("SecuroGuard quarantine failed", e);
                auditLog.error("quarantine failed: " + e.getMessage());
                deliver(onResult, false, "Quarantine failed: " + e.getMessage());
            }
        });
    }

    private void deliver(BiConsumer<Boolean, String> cb, boolean ok, String message) {
        if (cb != null) {
            MinecraftClient.getInstance().execute(() -> cb.accept(ok, message));
        }
    }

    public Optional<Baseline> loadBaselineQuietly() {
        try {
            return scanService.loadBaseline();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public void close() {
        for (FilesystemMonitor m : monitors.values()) {
            try {
                m.close();
            } catch (RuntimeException e) {
                LOG.warn("SecuroGuard error closing a monitor", e);
            }
        }
        monitors.clear();
        modsMonitor = null;
        worker.shutdownNow();
        auditLog.info("SecuroGuard stopped");
    }
}
