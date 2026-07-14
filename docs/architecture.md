# SecuroGuard Architecture

SecuroGuard is a Gradle multi-project build with three modules sharing one engine.

```
                 ┌─────────────────────────────────────────────┐
                 │              securoguard-core                │
                 │        (loader-neutral Java engine)          │
                 │                                              │
                 │  instance ─ inventory ─ baseline ─ monitor   │
                 │  jar ─ findings ─ quarantine ─ advisory      │
                 │  reputation ─ service (ScanService)          │
                 └───────────────▲───────────────▲──────────────┘
                                 │               │
              depends on         │               │  depends on
                                 │               │
        ┌────────────────────────┴───┐   ┌───────┴────────────────────┐
        │    securoguard-sentinel    │   │    securoguard-fabric       │
        │  external CLI, pre-launch  │   │  client-side Fabric mod     │
        │  (outside the game JVM)    │   │  (inside the game JVM)      │
        └────────────────────────────┘   └─────────────────────────────┘
```

## Design rules

- **Minecraft/Fabric dependencies never enter `securoguard-core`.** The core is
  plain Java 21 + Gson, so a future NeoForge adapter or another launcher can reuse
  it unchanged.
- **Adapters supply context; the core decides.** The Fabric mod supplies loader
  facts (authoritative game/mods dirs, loaded-mod origins, session/connection
  state). The core turns filesystem reality + context into findings.
- **Trust is only ever granted explicitly.** Discovering a file never trusts it;
  only an `approve` operation writes a new baseline.

## Core packages

| Package | Responsibility |
|---|---|
| `instance` | `InstancePaths` (game/mods/config/data/quarantine), `PathSecurity` (containment, zip-slip, link/junction detection). |
| `instance` | `InstancePaths`, `PathSecurity` (containment, zip-slip, `resolveContainedRelative`, link/junction detection), `ScanScope` (runtime/prelaunch/full). |
| `inventory` | `FileRecord`, `FileInventory`, `InventoryScanner` (scoped, single-read hash+type, `ScanLimits`, `ScopedScan` with skipped files), `InventoryDiff` → `DiffResult`, `InstalledMod` + `LoadedModIndex` (loader-neutral mod association). |
| `baseline` | `Baseline` (per-scope, schema v2), `BaselineStore` (versioned JSON, atomic writes, corruption preserved, old-schema rejected with a re-approve message). |
| `monitor` | `FilesystemMonitor` (NIO WatchService; coalescing bounded executor; **no scan on the watch thread**; overflow/periodic reconcile detects additions, modifications AND removals), `FileSettleTracker`, `MonitorHealth` (running/degraded/fatal/stopped). |
| `jar` | `JarInspector` — metadata-only, defensive limits (`JarInspectionLimits` incl. per-nested ratio, in-entry deadline, global memory budget), categorised `ArchiveIssue`, nested-jar declaration validation; never loads a class or runs an entry point, never asserts signer trust. |
| `findings` | `Finding`, `Severity`, `RecommendedAction`, `Rule`, `RuleEngine`, `RuleContext` (carries session + loaded mods + `baselineExists`), `BuiltinRules`. |
| `quarantine` | `QuarantineManager` — verified move, sidecar metadata, **containment-checked restore** (rebuilds target from `gameDir + validatedRelativePath`, full sidecar validation, link/junction refusal). |
| `advisory` | `Advisory`, `VersionRange`, `AdvisoryMatcher`, `AdvisoryFeed`, `AdvisorySource` (`BundledAdvisorySource`, `VerifiedAdvisorySource`), `AdvisoryFeedVerifier` (Ed25519), bundled Litematica/Servux feed. |
| `reputation` | `HashReputationProvider` (explicit `HashAlgorithm`), `MapReputationProvider` (offline/test), `ModrinthReputationProvider` (SHA-512, injectable `HttpTransport`, hash-only), `JdkHttpTransport`. |
| `service` | `ScanService` (the whole pipeline; scope-aware; advisory + loaded-mod aware), `ScanReport` (scope + skipped), `SecuroGuardConfig` (validated/clamped). |
| `util` | `Hashing` (SHA-256/512, single-pass hash+header), `HashAlgorithm`, `AtomicFiles`, `Json`, `AuditLog`. |

## The scan pipeline (`ScanService`)

```
load the per-scope baseline (or empty)
   → scoped scan → FileInventory (SHA-256 + type per file, one read each; skipped files reported)
   → associate loader-reported InstalledMods → set loadedAsMod + coordinates
   → diff current vs baseline  → DiffResult
   → inspect changed JARs (bounded, metadata-only)
   → optional hash reputation (SHA-512, offline unless enabled)
   → RuleEngine.evaluate(RuleContext{diff, session, inspections, reputation, malicious, baselineExists})
   → advisory matching over ALL installed mods (bundled/verified feed)
   → ScanReport{scope, diff, findings, currentInventory, skipped, truncated}
```

`approveCurrentAsBaseline(scope)` is the only trust-granting operation and is a
separate call from `scan(scope, …)`. With **no** baseline, "new since baseline" rules
stay silent (nothing to be new against), so a fresh install is not a wall of noise.

## Threading (Fabric side)

`SecuroGuardRuntime` guarantees no hashing, archive inspection, or filesystem write
happens on the render thread:

- Initial comparison and manual re-scans run on a dedicated single-thread executor,
  and rescans are **coalesced** (a burst of monitor events produces one scan).
- `FilesystemMonitor` runs its watch loop on its own thread and dispatches file
  scans and removals to a **bounded** executor. Its rejection policy never runs a
  scan on the watch thread — it sets a forced-reconciliation marker instead.
- The monitor exposes `MonitorHealth`; a fatal watcher failure flips it out of
  "active" and raises an unmistakable in-game warning, so SecuroGuard never claims to
  be monitoring after the watch thread has died.
- Only lightweight notifications (a chat warning, a screen refresh) hop back onto
  the client thread via `MinecraftClient.execute`.

## Extensibility

- **New rules**: implement `Rule` (a pure `RuleContext → List<Finding>`) and add it
  to a `RuleEngine`. No engine changes required.
- **New reputation source**: implement `HashReputationProvider`.
- **New loader**: build an adapter like `securoguard-fabric` that supplies
  `InstancePaths` and session context, then reuse `ScanService` unchanged.
