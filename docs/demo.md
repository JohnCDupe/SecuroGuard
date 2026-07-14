# SecuroGuard demonstration

Two ways to see the headline scenario — a harmless JAR added to `mods` producing a
CRITICAL finding and being safely quarantined.

## A. Automated (no setup)

The core test suite runs the whole scenario against the **real** monitor:

```bash
./gradlew :securoguard-core:test --tests "*EndToEndScenarioTest"
```

`EndToEndScenarioTest` builds a fake instance, approves a baseline, starts the
`FilesystemMonitor`, drops a harmless Fabric JAR into `mods` mid-"session",
receives a CRITICAL finding, quarantines it, and asserts it is gone from `mods`
with matching hash and sidecar metadata.

## B. Manual, with the built Sentinel CLI

This is the exact scenario used to verify this release (paths shown for Windows; adapt
for your OS). The Sentinel demonstrates the **pre-launch** boundary: a new,
untrusted JAR is flagged and can be quarantined without ever executing it.

```bash
# 1. Build the runnable Sentinel
./gradlew :securoguard-sentinel:installDist
BIN=securoguard-sentinel/build/install/securoguard/bin/securoguard   # .bat on Windows

# 2. Make a fake instance with one harmless, approved mod
mkdir -p /tmp/sg-demo/mods
#   (create /tmp/sg-demo/mods/sodium.jar as a small zip containing fabric.mod.json)

$BIN status  --game-dir /tmp/sg-demo                 # -> "Baseline: none",      exit 0
$BIN approve --game-dir /tmp/sg-demo --yes           # -> trusts sodium.jar,     exit 0
$BIN scan    --game-dir /tmp/sg-demo                 # -> "Findings: none",      exit 0

# 3. Simulate the attack: a disguised JAR appears in mods after approval
#   (create /tmp/sg-demo/mods/totally_safe.litematic.jar)
$BIN scan    --game-dir /tmp/sg-demo --redact        # -> HIGH new-untrusted-jar
                                                     #    HIGH double-extension
                                                     #    INFO unknown-hash,     exit 1

# 4. Quarantine it (explicit action), then re-scan
$BIN quarantine --game-dir /tmp/sg-demo --file /tmp/sg-demo/mods/totally_safe.litematic.jar
$BIN scan       --game-dir /tmp/sg-demo              # -> "Findings: none",      exit 0
```

After step 4:

- `mods/` contains only `sodium.jar` — the disguised JAR is gone.
- `securoguard/quarantine/` contains `…​.quarantined` (not a loadable `.jar`) plus a
  `…​.json` sidecar with the original path, SHA-256, timestamp, and triggering
  findings.
- Restore any time with `$BIN restore --game-dir /tmp/sg-demo --item <id> --yes`.

> In-game, the Fabric mod raises the same detection **live** (CRITICAL, because a
> session is active) and offers a confirmed **Quarantine** button on the SecuroGuard
> findings screen.

## C. Advisory (known-vulnerable mod) demonstration

```bash
mkdir -p /tmp/sg-adv/mods
#   create /tmp/sg-adv/mods/litematica.jar whose fabric.mod.json is
#   {"schemaVersion":1,"id":"litematica","version":"0.26.10"}
$BIN approve --game-dir /tmp/sg-adv --yes
$BIN scan    --game-dir /tmp/sg-adv --mc-version 1.21.11
#   -> [HIGH] SG-ADVISORY — Known-vulnerable mod: litematica 0.26.10
#      evidence: advisory=SG-ADV-2026-07-LITEMATICA-1.21.11 fixed=0.26.11 …   exit 1
```

Bumping the jar's version to `0.26.11` (the fixed version for 1.21.11) and re-scanning
produces **no** advisory finding. Using `--mc-version 1.21.4` with version `0.21.6`
matches that line's advisory instead (fixed `0.21.7`).

## D. Scope demonstration (runtime scans ignore worlds/logs)

```bash
# With saves/ and logs/ present in the instance:
$BIN scan --game-dir /tmp/sg-demo --scope runtime   # inventories mods only
$BIN scan --game-dir /tmp/sg-demo --scope full      # inventories the whole instance (slow)
```

This is also covered deterministically by `ScanScopeTest` in the core suite, which
asserts a runtime scan never hashes `saves/` or `logs/`.

## E. Fabric dev-client smoke test

`./gradlew :securoguard-fabric:runClient` launches a real Fabric development client.

**Verified automatically in this environment** (from `run/logs/latest.log` and
`run/securoguard/logs/securoguard.log`):

- ✅ Fabric **discovers** the mod — `securoguard 0.1.0+mc1.21.11` appears in the loaded
  mod list and the resource-reload manifest.
- ✅ The **nested core jar loads** — `onInitializeClient` runs code that uses
  `securoguard-core` classes and logs `SecuroGuard initialised for …`.
- ✅ **Client initialization completes** and the game reaches the **main menu**.
- ✅ **Monitoring starts** — the audit log records `Monitoring mods directory: …/run/mods`.
- ✅ **Mod Menu integration does not crash** when Mod Menu is present (only a cosmetic
  "broken icon" warning, because no `icon.png` is shipped yet).
- ✅ **No exceptions** originate from any `com.securoguard` code during startup.

**Not verified automatically** (require driving the GUI / an in-world session, which
this environment cannot automate — do NOT assume these are proven):

- ⏳ Opening the **SecuroGuard status/findings screen** via Mod Menu → Configure.
- ⏳ Executing `/securoguard status|scan|findings` (client commands activate on world
  join; the registration callback is installed at init without error).
- ⏳ Behaviour with **Mod Menu absent** (this run had Mod Menu present).
- ⏳ A **live CRITICAL finding** from a JAR drop (needs an approved runtime baseline
  and an active session).

### Manual smoke-test checklist (for the project owner)

1. `./gradlew :securoguard-fabric:runClient`; wait for the main menu.
2. **Mod Menu → SecuroGuard → Configure** → the status screen opens and shows
   Monitoring (health), Baseline, Findings, Session lines.
3. Create a single-player world (session becomes active).
4. In a terminal: `securoguard approve --game-dir <…>/securoguard-fabric/run --scope runtime --yes`.
5. Copy a harmless mod JAR into `run/mods`. Within ~1–2s a **CRITICAL** chat warning
   appears (new JAR during an active session).
6. Open the findings screen → the finding shows severity, rule id, path, SHA-256,
   explanation, recommended action. Click **Quarantine…** → confirm → the file leaves
   `run/mods` and a success line appears.
7. If connected to a multiplayer server with a HIGH/CRITICAL finding, the
   **Disconnect** button ends the session using the normal client disconnect.
8. Set `quarantineEnabled: false` in `run/config/securoguard.json`, relaunch → the
   in-game Quarantine button is not offered; the Sentinel `quarantine` command still works.
9. Remove Mod Menu from `run/mods` (or the dependency) → SecuroGuard still loads and
   `/securoguard` commands still work; only the Mod Menu button is gone.
