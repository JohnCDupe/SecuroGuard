package com.securoguard.sentinel;

import com.securoguard.core.advisory.BundledAdvisorySource;
import com.securoguard.core.baseline.Baseline;
import com.securoguard.core.baseline.BaselineException;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.monitor.FilesystemMonitor;
import com.securoguard.core.monitor.MonitorListener;
import com.securoguard.core.quarantine.QuarantineItem;
import com.securoguard.core.quarantine.QuarantineManager;
import com.securoguard.core.reputation.HashReputationProvider;
import com.securoguard.core.reputation.ModrinthReputationProvider;
import com.securoguard.core.service.ScanReport;
import com.securoguard.core.service.ScanService;
import com.securoguard.core.service.SecuroGuardConfig;

import java.io.PrintStream;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The Sentinel command dispatcher. All logic returns an {@link ExitCode} and
 * writes to injected streams, so every command is unit-testable in-process
 * without spawning a JVM. {@link SentinelMain} is the thin {@code System.exit}
 * wrapper around this.
 */
public final class Sentinel {

    private final PrintStream out;
    private final PrintStream err;

    public Sentinel(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public int run(String[] argv) {
        Args args = Args.parse(argv);
        try {
            return switch (args.command()) {
                case "scan" -> scan(args);
                case "status" -> status(args);
                case "approve" -> approve(args);
                case "quarantine" -> quarantine(args);
                case "restore" -> restore(args);
                case "watch" -> watch(args);
                case "help", "", "--help" -> {
                    printUsage(out);
                    yield ExitCode.OK;
                }
                default -> {
                    err.println("Unknown command: " + args.command());
                    printUsage(err);
                    yield ExitCode.CONFIG_ERROR;
                }
            };
        } catch (ConfigError e) {
            err.println("Configuration error: " + e.getMessage());
            return ExitCode.CONFIG_ERROR;
        } catch (Exception e) {
            err.println("Internal error: " + e);
            return ExitCode.INTERNAL_ERROR;
        }
    }

    // --- commands ---

    private int scan(Args args) throws Exception {
        Context ctx = context(args);
        warnIfMcVersionMissing(args);
        ScanReport report = ctx.scanService.scan(false, false);
        boolean redact = args.has("redact");

        out.println("SecuroGuard scan: " + ctx.paths.gameDir());
        out.println("Scope: " + report.scope().id());
        out.println("Baseline: " + (report.baselineExisted() ? "present" : "MISSING (nothing is trusted yet)"));
        if (report.truncated()) {
            out.println("WARNING: scan truncated by the file-count limit; results are incomplete.");
        }
        if (!report.skipped().isEmpty()) {
            out.println("Skipped " + report.skipped().size() + " file(s) (oversized/unreadable):");
            report.skipped().stream().limit(10).forEach(s ->
                    out.println("  - " + s.relativePath() + " (" + s.reason() + ")"));
        }
        out.println("Changes vs baseline: " + report.diff().totalChanges()
                + " (added=" + report.diff().added().size()
                + ", removed=" + report.diff().removed().size()
                + ", modified=" + report.diff().modified().size()
                + ", replaced=" + report.diff().replaced().size()
                + ", renamed=" + report.diff().renamed().size() + ")");
        printFindings(report.findings(), ctx.paths, redact);

        return exitFor(report.findings());
    }

    private int status(Args args) throws Exception {
        Context ctx = context(args);
        out.println("SecuroGuard status: " + ctx.paths.gameDir());
        Optional<Baseline> baseline;
        try {
            baseline = ctx.scanService.loadBaseline();
        } catch (BaselineException e) {
            out.println("Baseline: CORRUPT (" + e.getMessage() + ")");
            baseline = Optional.empty();
        }
        if (baseline.isPresent()) {
            out.println("Baseline: present, " + baseline.get().inventory().size()
                    + " trusted files, updated " + baseline.get().updatedAt());
        } else {
            out.println("Baseline: none. Run 'approve' to establish trust.");
        }
        out.println("Monitor: not running (Sentinel is a pre-launch/one-shot tool; use 'watch' to monitor).");
        QuarantineManager qm = new QuarantineManager(ctx.paths);
        out.println("Quarantined items: " + qm.list().size());
        int orphans = qm.listFailures().size();
        if (orphans > 0) {
            out.println("Orphaned quarantine failures (need manual recovery): " + orphans);
        }
        return ExitCode.OK;
    }

    private int approve(Args args) throws Exception {
        Context ctx = context(args);
        // Trust is only granted with explicit confirmation. --yes enables scripting.
        if (!args.has("yes")) {
            err.println("Refusing to replace the trusted baseline without confirmation.");
            err.println("Re-run with --yes to approve the current instance state as trusted.");
            return ExitCode.CONFIG_ERROR;
        }
        Baseline baseline = ctx.scanService.approveCurrentAsBaseline();
        out.println("Approved new baseline (scope=" + baseline.scope().id() + "): "
                + baseline.inventory().size() + " files trusted at " + baseline.updatedAt());
        return ExitCode.OK;
    }

    private int quarantine(Args args) throws Exception {
        Context ctx = context(args);
        String fileArg = args.get("file");
        if (fileArg == null) {
            throw new ConfigError("quarantine requires --file <path>");
        }
        Path file = Path.of(fileArg).toAbsolutePath().normalize();
        QuarantineManager qm = new QuarantineManager(ctx.paths);
        QuarantineItem item = qm.quarantine(file, List.of());
        out.println("Quarantined: " + item.originalRelativePath());
        out.println("  id=" + item.id());
        out.println("  sha256=" + item.sha256());
        out.println("  stored=" + item.storedFileName());
        return ExitCode.OK;
    }

    private int restore(Args args) throws Exception {
        Context ctx = context(args);
        String id = args.get("item");
        if (id == null) {
            throw new ConfigError("restore requires --item <id>");
        }
        if (!args.has("yes")) {
            err.println("Refusing to restore without confirmation. Re-run with --yes.");
            return ExitCode.CONFIG_ERROR;
        }
        QuarantineManager qm = new QuarantineManager(ctx.paths);
        Path restored = qm.restore(id, true);
        out.println("Restored to: " + restored);
        return ExitCode.OK;
    }

    private int watch(Args args) throws Exception {
        Context ctx = context(args);
        Severity threshold = minSeverity(args, Severity.HIGH); // default: alert on HIGH and above
        warnIfMcVersionMissing(args);
        out.println("Watching " + ctx.paths.modsDir() + " (min-severity=" + threshold
                + ", Ctrl+C to stop)...");

        WatchSession session = new WatchSession(ctx.scanService, out, ctx.paths, args.has("redact"), threshold);
        java.util.concurrent.atomic.AtomicInteger exit =
                new java.util.concurrent.atomic.AtomicInteger(ExitCode.OK);
        Thread main = Thread.currentThread();

        MonitorListener listener = new MonitorListener() {
            @Override public void onFileSettled(Path file) {
                session.onChange();
            }
            @Override public void onFileRemoved(Path file) {
                session.onChange();
            }
            @Override public void onReconciled(Set<Path> currentFiles) {
                session.onChange();
            }
            @Override public void onFailure(String message, Throwable cause, boolean fatal) {
                err.println("[monitor " + (fatal ? "FATAL" : "warn") + "] " + message);
                if (fatal) {
                    // Fatal monitor termination is a meaningful, non-OK outcome.
                    exit.set(ExitCode.INTERNAL_ERROR);
                    main.interrupt();
                }
            }
        };
        try (FilesystemMonitor monitor = new FilesystemMonitor(ctx.paths.modsDir(), listener,
                ctx.config.watchQuietPeriodMillis, 500, ctx.config.reconcileIntervalMillis,
                System::currentTimeMillis)) {
            monitor.start();
            session.onChange(); // establish the initial baseline of already-present findings
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        return exit.get();
    }

    // --- helpers ---

    private Context context(Args args) {
        String gameDirArg = args.get("game-dir");
        if (gameDirArg == null || gameDirArg.isBlank()) {
            throw new ConfigError("missing required --game-dir <path>");
        }
        Path gameDir = Path.of(gameDirArg);
        InstancePaths paths = InstancePaths.ofGameDir(gameDir);
        try {
            paths.createDataDirectories();
        } catch (Exception e) {
            throw new ConfigError("cannot create SecuroGuard data dir under " + paths.dataDir() + ": " + e);
        }
        SecuroGuardConfig config = SecuroGuardConfig.loadOrDefault(paths.configDir().resolve("securoguard.json"));
        // Surface any config corrections rather than silently accepting bad values.
        for (String w : config.warnings()) {
            err.println("[config] " + w);
        }
        // Sentinel defaults to the pre-launch scope; --scope overrides it.
        ScanScope scope = ScanScope.PRELAUNCH;
        if (args.has("scope")) {
            scope = ScanScope.fromId(args.get("scope"));
            if (scope == null) {
                throw new ConfigError("unknown --scope (use runtime, prelaunch or full)");
            }
        }
        boolean online = args.has("online") || config.onlineReputationEnabled;
        HashReputationProvider reputation = online ? new ModrinthReputationProvider() : null;
        Set<String> malicious = new HashSet<>(config.knownMaliciousHashes);
        ScanService scanService = new ScanService(paths, RuleEngine.withDefaultRules(), reputation, malicious)
                // Trusted, offline, bundled advisory feed. Remote feeds would require
                // Ed25519 verification (VerifiedAdvisorySource) and are not fetched here.
                .withAdvisorySource(new BundledAdvisorySource())
                .withMinecraftVersion(args.get("mc-version"))
                .withDefaultScope(scope)
                .withMonitoredDirectories(config.monitoredDirectories)
                .withScanLimits(config.scanLimits());
        return new Context(paths, config, scanService);
    }

    private void printFindings(List<Finding> findings, InstancePaths paths, boolean redact) {
        if (findings.isEmpty()) {
            out.println("Findings: none.");
            return;
        }
        out.println("Findings (" + findings.size() + "):");
        for (Finding f : findings) {
            out.println("  [" + f.severity() + "] " + f.ruleId() + " — " + f.title());
            if (f.affectedPath() != null) {
                out.println("      path: " + f.affectedPath());
            }
            out.println("      " + redactIfNeeded(f.explanation(), paths, redact));
            if (!f.evidence().isBlank()) {
                out.println("      evidence: " + redactIfNeeded(f.evidence(), paths, redact));
            }
            out.println("      recommended: " + f.recommendedAction());
        }
    }

    /** When redaction is requested, replace the absolute instance path with a placeholder. */
    private String redactIfNeeded(String text, InstancePaths paths, boolean redact) {
        if (!redact || text == null) {
            return text;
        }
        return text.replace(paths.gameDir().toString(), "<instance>")
                .replace(System.getProperty("user.home", "~"), "<home>");
    }

    /** Parses {@code --min-severity}, rejecting invalid values as config errors. */
    private Severity minSeverity(Args args, Severity fallback) {
        String s = args.get("min-severity");
        if (s == null || s.isBlank()) {
            return fallback;
        }
        try {
            return Severity.valueOf(s.trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ConfigError("invalid --min-severity '" + s + "' (use info, low, medium, high or critical)");
        }
    }

    /** Warns (once) that coordinate advisory matching is degraded when no MC version is given. */
    private void warnIfMcVersionMissing(Args args) {
        String mc = args.get("mc-version");
        if (mc == null || mc.isBlank()) {
            err.println("[advisory] --mc-version not supplied; coordinate advisory matching may be "
                    + "incomplete (SecuroGuard will not guess the Minecraft line). Hash and behavioural "
                    + "checks still run. Pass --mc-version <v> for precise per-Minecraft-line advisories.");
        }
    }

    private int exitFor(List<Finding> findings) {
        boolean critical = findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL);
        if (critical) {
            return ExitCode.CRITICAL;
        }
        boolean warn = findings.stream().anyMatch(f -> f.severity().compareTo(Severity.MEDIUM) >= 0);
        return warn ? ExitCode.WARNINGS : ExitCode.OK;
    }

    static void printUsage(PrintStream s) {
        s.println("""
                SecuroGuard Sentinel — pre-launch Minecraft instance scanner

                Usage: securoguard <command> [options]

                Commands:
                  scan       --game-dir <path> [--scope prelaunch|runtime|full] [--mc-version <v>] [--online] [--redact]
                                                                       Scan and compare against the baseline
                  status     --game-dir <path> [--scope <s>]           Show baseline/quarantine status
                  approve    --game-dir <path> [--scope <s>] --yes     Trust the current instance state
                  quarantine --game-dir <path> --file <path>           Move a file into quarantine
                  restore    --game-dir <path> --item <id> --yes       Restore a quarantined file
                  watch      --game-dir <path> [--scope <s>] [--min-severity high] [--mc-version <v>] [--redact]
                                                                       Monitor continuously; alert on new findings

                Scopes: prelaunch (mods+config, default), runtime (mods + configured dirs), full (whole instance, slow)
                --min-severity: info|low|medium|high|critical  (watch default: high)
                --mc-version:  required for precise per-Minecraft-line advisory matching (never guessed from filenames)
                Exit codes: 0 ok, 1 warnings, 2 critical, 3 config error, 4 internal error
                """);
    }

    private record Context(InstancePaths paths, SecuroGuardConfig config, ScanService scanService) {
    }

    /** Signals a user/config problem that should map to {@link ExitCode#CONFIG_ERROR}. */
    private static final class ConfigError extends RuntimeException {
        ConfigError(String message) {
            super(message);
        }
    }
}
