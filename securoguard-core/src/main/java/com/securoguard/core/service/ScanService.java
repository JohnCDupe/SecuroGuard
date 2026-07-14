package com.securoguard.core.service;

import com.securoguard.core.advisory.Advisory;
import com.securoguard.core.advisory.AdvisoryFeed;
import com.securoguard.core.advisory.AdvisoryLoad;
import com.securoguard.core.advisory.AdvisoryMatcher;
import com.securoguard.core.advisory.AdvisorySource;
import com.securoguard.core.baseline.Baseline;
import com.securoguard.core.baseline.BaselineException;
import com.securoguard.core.baseline.BaselineStore;
import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RecommendedAction;
import com.securoguard.core.findings.RuleContext;
import com.securoguard.core.findings.RuleEngine;
import com.securoguard.core.findings.Severity;
import com.securoguard.core.jar.ModMetadata;
import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.instance.ScanScope;
import com.securoguard.core.inventory.DiffResult;
import com.securoguard.core.inventory.ScanLimits;
import com.securoguard.core.inventory.ScopedScan;
import com.securoguard.core.inventory.FileInventory;
import com.securoguard.core.inventory.FileRecord;
import com.securoguard.core.inventory.InstalledMod;
import com.securoguard.core.inventory.InventoryDiff;
import com.securoguard.core.inventory.InventoryScanner;
import com.securoguard.core.inventory.LoadedModIndex;
import com.securoguard.core.jar.JarInspectionResult;
import com.securoguard.core.jar.JarInspector;
import com.securoguard.core.reputation.HashReputationProvider;
import com.securoguard.core.reputation.ReputationResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The loader-neutral orchestration used by both the Sentinel and the Fabric mod.
 * It performs the full pipeline: scan → diff against baseline → inspect changed
 * JARs → optional hash reputation → run rules. It never mutates trust implicitly;
 * approving a new baseline is a separate, explicit call.
 */
public final class ScanService {

    private final InstancePaths paths;
    private final InventoryScanner scanner;
    private final JarInspector jarInspector;
    private final RuleEngine ruleEngine;
    private final HashReputationProvider reputationProvider; // nullable => offline only
    private final Set<String> knownMaliciousHashes;
    private List<InstalledMod> loadedMods = List.of();
    private AdvisorySource advisorySource; // nullable => advisory matching disabled
    private String minecraftVersion;       // nullable => MC-range check skipped
    private ScanScope defaultScope = ScanScope.FULL;
    private List<String> monitoredDirs = List.of();
    private ScanLimits scanLimits = ScanLimits.defaults();

    public ScanService(InstancePaths paths, RuleEngine ruleEngine,
                       HashReputationProvider reputationProvider, Set<String> knownMaliciousHashes) {
        this.paths = paths;
        this.scanner = new InventoryScanner(paths);
        this.jarInspector = new JarInspector();
        this.ruleEngine = ruleEngine;
        this.reputationProvider = reputationProvider;
        this.knownMaliciousHashes = knownMaliciousHashes;
    }

    private BaselineStore baselineStore(ScanScope scope) {
        return new BaselineStore(paths.baselineFile(scope), paths.gameDir());
    }

    /** Sets the scope used by the no-argument scan/approve/load methods. */
    public ScanService withDefaultScope(ScanScope scope) {
        this.defaultScope = scope == null ? ScanScope.FULL : scope;
        return this;
    }

    /** Instance-relative additional directories to include in RUNTIME/PRELAUNCH scopes. */
    public ScanService withMonitoredDirectories(List<String> relativeDirs) {
        this.monitoredDirs = relativeDirs == null ? List.of() : List.copyOf(relativeDirs);
        return this;
    }

    /** Bounds on file count and per-file size for scans. */
    public ScanService withScanLimits(ScanLimits limits) {
        this.scanLimits = limits == null ? ScanLimits.defaults() : limits;
        return this;
    }

    /**
     * Supplies the loader's view of installed mods (Fabric adapter). Files whose
     * absolute path matches a mod origin are marked {@code loadedAsMod} and their
     * mod coordinates are preserved for advisory matching. Returns {@code this}.
     */
    public ScanService withLoadedMods(List<InstalledMod> mods) {
        this.loadedMods = mods == null ? List.of() : List.copyOf(mods);
        return this;
    }

    /**
     * Supplies a trusted advisory source. Advisory matches become findings in every
     * scan. A {@code null} source (the default) disables advisory matching entirely.
     */
    public ScanService withAdvisorySource(AdvisorySource source) {
        this.advisorySource = source;
        return this;
    }

    /** Sets the instance's Minecraft version so advisory Minecraft-line ranges apply. */
    public ScanService withMinecraftVersion(String mcVersion) {
        this.minecraftVersion = (mcVersion == null || mcVersion.isBlank()) ? null : mcVersion;
        return this;
    }

    /** Runs a scan at the configured default scope (see {@link #withDefaultScope}). */
    public ScanReport scan(boolean sessionActive, boolean connectedToServer)
            throws IOException, BaselineException {
        return scan(defaultScope, sessionActive, connectedToServer);
    }

    /**
     * Runs a scan at an explicit {@link ScanScope}. The diff is computed against the
     * baseline captured with the <em>same</em> scope, so runtime scans are not
     * compared against full-instance baselines.
     */
    public ScanReport scan(ScanScope scope, boolean sessionActive, boolean connectedToServer)
            throws IOException, BaselineException {
        Optional<Baseline> baselineOpt = baselineStore(scope).load();
        FileInventory baselineInventory = baselineOpt
                .map(Baseline::inventory)
                .orElse(FileInventory.empty());

        ScopedScan scoped = scanner.scanScoped(scope, resolveMonitoredDirs(), scanLimits);
        Map<String, InstalledMod> modByRelPath = new HashMap<>();
        FileInventory current = associateLoadedMods(scoped.inventory(), modByRelPath);

        DiffResult diff = InventoryDiff.compute(baselineInventory, current);

        Map<String, JarInspectionResult> inspections = inspectChangedJars(diff);
        Map<String, ReputationResult> reputation = lookupReputation(diff);

        RuleContext ctx = RuleContext.builder(diff)
                .sessionActive(sessionActive)
                .connectedToServer(connectedToServer)
                .inspections(inspections)
                .knownMaliciousHashes(knownMaliciousHashes)
                .reputation(reputation)
                .loadedMods(modByRelPath)
                .baselineExists(baselineOpt.isPresent())
                .build();

        List<Finding> findings = new java.util.ArrayList<>(ruleEngine.evaluate(ctx));
        // Advisory matching considers ALL currently-installed mods (not just the diff),
        // so a vulnerable mod present since the baseline is still flagged pre-launch.
        findings.addAll(advisoryFindings(current, modByRelPath));
        findings.sort(java.util.Comparator.comparing(Finding::severity).reversed());
        return new ScanReport(scope, baselineOpt.isPresent(), diff, findings, current,
                scoped.skipped(), scoped.truncated());
    }

    /** Resolves configured monitored directories to safe, instance-contained absolute paths. */
    private List<Path> resolveMonitoredDirs() {
        List<Path> out = new java.util.ArrayList<>();
        for (String rel : monitoredDirs) {
            Path dir = paths.resolveMonitoredDir(rel); // null if it escapes the instance
            if (dir != null) {
                out.add(dir);
            }
        }
        return out;
    }

    /**
     * Matches every installed mod against the advisory feed and converts hits into
     * findings. Coordinates come from the loader when available (Fabric), otherwise
     * from each jar's fabric.mod.json. Malformed/unknown versions never crash the scan.
     *
     * <p>If the advisory feed cannot be loaded/verified, emits exactly one MEDIUM
     * <em>degraded-protection</em> finding (never "everything is safe"). If required
     * coordinates (Minecraft version / loader) are missing so coordinate advisories
     * cannot be applied precisely, emits exactly one LOW "matching incomplete" finding.
     */
    private List<Finding> advisoryFindings(FileInventory current, Map<String, InstalledMod> modByRelPath) {
        List<Finding> out = new java.util.ArrayList<>();
        if (advisorySource == null) {
            return out;
        }
        AdvisoryLoad load;
        try {
            load = advisorySource.load();
        } catch (RuntimeException e) {
            load = AdvisoryLoad.failure(AdvisoryLoad.Status.PARSE_ERROR, "unexpected error loading feed");
        }
        if (load.isFailure()) {
            // Degraded protection: advisory checks are unavailable. Surface once; never
            // treat this as "no advisories apply". Behavioural/hash scanning continues.
            out.add(Finding.builder("SG-ADVISORY-UNAVAILABLE", Severity.MEDIUM)
                    .title("Advisory checking is unavailable (" + load.status() + ")")
                    .explanation("The advisory feed could not be loaded or verified, so SecuroGuard could "
                            + "NOT check installed mods against known vulnerabilities this scan. This is a "
                            + "degraded-protection state, not a clean result. Other checks still ran.")
                    .evidence("status=" + load.status()
                            + (load.detail() != null ? " detail=" + load.detail() : ""))
                    .recommend(RecommendedAction.REVIEW)
                    .build());
            return out;
        }
        AdvisoryFeed feed = load.feed();
        if (feed.advisories().isEmpty()) {
            return out; // legitimately empty feed
        }
        AdvisoryMatcher matcher = new AdvisoryMatcher(feed);
        java.util.EnumSet<AdvisoryMatcher.Incomplete> incomplete =
                java.util.EnumSet.noneOf(AdvisoryMatcher.Incomplete.class);
        for (FileRecord r : current.records()) {
            if (!r.fileName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                continue;
            }
            String modId = null;
            String version = null;
            String loader = null;
            InstalledMod loaded = modByRelPath.get(r.relativePath());
            if (loaded != null) {
                modId = loaded.modId();
                version = loaded.version();
                loader = loaded.loader();
            } else {
                ModMetadata meta = readModMetadata(r);
                if (meta != null) {
                    modId = meta.modId();
                    version = meta.version();
                    // A fabric.mod.json inherently means the Fabric loader.
                    loader = "fabric";
                }
            }
            if (modId == null) {
                continue; // not a coordinate-bearing mod jar
            }
            AdvisoryMatcher.MatchResult result = matcher.evaluate(
                    new AdvisoryMatcher.Query(modId, loader, minecraftVersion, version, r.sha256()));
            incomplete.addAll(result.incomplete());
            for (Advisory a : result.matches()) {
                out.add(advisoryFinding(a, r, modId, version));
            }
        }
        if (!incomplete.isEmpty()) {
            out.add(incompleteFinding(incomplete));
        }
        return out;
    }

    /** One aggregate finding explaining which coordinate(s) blocked precise matching. */
    private Finding incompleteFinding(java.util.EnumSet<AdvisoryMatcher.Incomplete> incomplete) {
        java.util.List<String> missing = new java.util.ArrayList<>();
        if (incomplete.contains(AdvisoryMatcher.Incomplete.MINECRAFT_VERSION_UNKNOWN)) {
            missing.add("Minecraft version");
        }
        if (incomplete.contains(AdvisoryMatcher.Incomplete.LOADER_UNKNOWN)) {
            missing.add("loader");
        }
        return Finding.builder("SG-ADVISORY-INCOMPLETE", Severity.LOW)
                .title("Advisory matching incomplete: missing " + String.join(", ", missing))
                .explanation("Some coordinate advisories could not be applied because required context was "
                        + "unknown, so SecuroGuard did NOT guess. Supply the missing coordinate (e.g. the "
                        + "Sentinel's --mc-version) for precise advisory matching. Hash and behavioural checks "
                        + "still ran.")
                .evidence("missing=" + String.join(",", missing))
                .recommend(RecommendedAction.REVIEW)
                .build();
    }

    private Finding advisoryFinding(Advisory a, FileRecord r, String modId, String version) {
        Severity severity = parseSeverity(a.severity());
        String fixed = a.fixedVersions() == null || a.fixedVersions().isEmpty()
                ? "see advisory" : String.join(", ", a.fixedVersions());
        return Finding.builder("SG-ADVISORY", severity)
                .title("Known-vulnerable mod: " + modId + " " + (version == null ? "(unknown version)" : version))
                .explanation("An installed mod matches a security advisory. Update it to a fixed version. "
                        + "SecuroGuard reports the advisory match; it does not itself exploit or verify the flaw.")
                .evidence("advisory=" + a.id()
                        + " installedVersion=" + version
                        + " affected=" + describeRanges(a)
                        + " fixed=" + fixed
                        + " references=" + a.references())
                .affectedPath(r.relativePath())
                .recommend(RecommendedAction.UPDATE)
                .build();
    }

    private static String describeRanges(Advisory a) {
        if (a.affectedRanges() == null || a.affectedRanges().isEmpty()) {
            return "all versions";
        }
        StringBuilder sb = new StringBuilder();
        for (var range : a.affectedRanges()) {
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append('[').append(range.introduced() == null ? "*" : range.introduced())
                    .append(", ").append(range.fixed() == null ? "*" : range.fixed()).append(')');
        }
        return sb.toString();
    }

    private static Severity parseSeverity(String s) {
        if (s == null) {
            return Severity.MEDIUM;
        }
        try {
            return Severity.valueOf(s.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return Severity.MEDIUM;
        }
    }

    /** Reads a jar's fabric.mod.json metadata for advisory coordinates (Sentinel path). */
    private ModMetadata readModMetadata(FileRecord r) {
        try {
            return jarInspector.inspect(Path.of(r.absolutePath())).modMetadata().orElse(null);
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }

    /**
     * Explicitly replaces the trusted baseline with the current state of the
     * instance. This is the only operation that grants trust. Callers are expected
     * to have obtained user confirmation first.
     */
    /** Approves the current instance state at the default scope. */
    public Baseline approveCurrentAsBaseline() throws IOException {
        return approveCurrentAsBaseline(defaultScope);
    }

    /**
     * Explicitly replaces the trusted baseline for {@code scope} with the current
     * scoped state. This is the only operation that grants trust; callers are
     * expected to have obtained user confirmation first.
     */
    public Baseline approveCurrentAsBaseline(ScanScope scope) throws IOException {
        FileInventory current = scanner.scanScoped(scope, resolveMonitoredDirs(), scanLimits).inventory();
        BaselineStore store = baselineStore(scope);
        Baseline baseline;
        try {
            Optional<Baseline> existing = store.load();
            baseline = existing.map(b -> b.replaceInventory(current)).orElse(Baseline.create(current, scope));
        } catch (BaselineException corrupt) {
            // A corrupt prior baseline was preserved by the store; start fresh.
            baseline = Baseline.create(current, scope);
        }
        store.save(baseline);
        return baseline;
    }

    public Optional<Baseline> loadBaseline() throws IOException, BaselineException {
        return loadBaseline(defaultScope);
    }

    public Optional<Baseline> loadBaseline(ScanScope scope) throws IOException, BaselineException {
        return baselineStore(scope).load();
    }

    /**
     * Rebuilds the inventory with {@code loadedAsMod} set for files that match a
     * loader-reported mod origin, and records the mod coordinates per relative path
     * (for advisory matching). Files not matching any origin are returned unchanged.
     */
    private FileInventory associateLoadedMods(FileInventory raw, Map<String, InstalledMod> outModByRelPath) {
        if (loadedMods.isEmpty()) {
            return raw;
        }
        LoadedModIndex index = new LoadedModIndex(loadedMods);
        if (index.isEmpty()) {
            return raw;
        }
        List<FileRecord> associated = new java.util.ArrayList<>(raw.size());
        for (FileRecord r : raw.records()) {
            InstalledMod mod = index.forAbsolutePath(r.absolutePath()).orElse(null);
            if (mod != null) {
                outModByRelPath.put(r.relativePath(), mod);
                associated.add(r.loadedAsMod() ? r : r.withLoadedAsMod(true));
            } else {
                associated.add(r);
            }
        }
        return FileInventory.of(associated);
    }

    private Map<String, JarInspectionResult> inspectChangedJars(DiffResult diff) {
        Map<String, JarInspectionResult> map = new HashMap<>();
        for (FileRecord r : changed(diff)) {
            if (!r.fileName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                continue;
            }
            Path abs = Path.of(r.absolutePath());
            try {
                map.put(r.relativePath(), jarInspector.inspect(abs));
            } catch (IOException e) {
                // Unreadable now (perhaps just moved/removed); the diff still stands.
                map.put(r.relativePath(),
                        JarInspectionResult.unreadable("Could not read archive for inspection: " + e.getMessage()));
            }
        }
        return map;
    }

    private Map<String, ReputationResult> lookupReputation(DiffResult diff) {
        Map<String, ReputationResult> map = new HashMap<>();
        if (reputationProvider == null) {
            return map;
        }
        // Providers declare which hash they need (Modrinth needs SHA-512). We compute
        // exactly that hash, but key the result by the file's SHA-256 so the rule
        // engine keeps using SHA-256 as the internal file identity.
        com.securoguard.core.util.HashAlgorithm alg = reputationProvider.requiredAlgorithm();
        for (FileRecord r : diff.added()) {
            if (!r.fileName().toLowerCase(Locale.ROOT).endsWith(".jar")) {
                continue;
            }
            String hex;
            if (alg == com.securoguard.core.util.HashAlgorithm.SHA256) {
                hex = r.sha256();
            } else {
                Path abs = Path.of(r.absolutePath());
                // R7: never re-hash through a symlink/redirect for a reputation lookup.
                if (InventoryScanner.linkSkipReason(abs) != null) {
                    continue;
                }
                try {
                    hex = com.securoguard.core.util.Hashing.hash(alg, abs);
                } catch (IOException e) {
                    continue; // unreadable now (e.g. just moved); skip reputation for it
                }
            }
            map.put(r.sha256(), reputationProvider.lookup(hex));
        }
        return map;
    }

    private static List<FileRecord> changed(DiffResult diff) {
        List<FileRecord> out = new java.util.ArrayList<>(diff.added());
        diff.modified().forEach(c -> out.add(c.after()));
        diff.replaced().forEach(c -> out.add(c.after()));
        diff.renamed().forEach(r -> out.add(r.to()));
        return out;
    }
}
