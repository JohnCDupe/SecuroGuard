# SecuroGuard Threat Model

## Protected assets

- The integrity of the instance's `mods` directory and other instance files
  between the moment they are approved and the next launch.
- The player's awareness: timely, honest warning when the trusted set changes.
- Evidence: a preserved copy and metadata of a suspicious file for later review.
- The player's privacy: no server addresses, tokens, telemetry, or JAR uploads.

## Components and trust

| Component | Runs | Trust |
|---|---|---|
| **Sentinel** | Separate process, before Minecraft starts | **Trusted boundary.** No mod code is running yet. |
| **Fabric mod** | Inside the Minecraft JVM | **Limited.** Equal privileges to every other mod. |
| **securoguard-core** | Library within either | As trusted as its host process. |
| Other mods | Inside the Minecraft JVM | **Untrusted** with respect to this threat model. |
| A joined server | Remote | **Untrusted.** May attempt to exploit a vulnerable mod. |

## Primary in-scope threat

1. Minecraft starts with a known, approved set of mod JARs.
2. The player joins a server.
3. A vulnerable mod is exploited by the server (e.g. an arbitrary-file-write bug).
4. A **new malicious JAR is written into `mods`.**
5. The JAR is intended to execute on a **later** launch.

SecuroGuard is designed to **detect step 4 as it happens** (Fabric mod, CRITICAL
finding) and/or **before step 5** (Sentinel pre-launch scan), warn the player,
preserve evidence, and offer quarantine — **without ever executing the file.**

Other in-scope detections: modification of an existing mod JAR mid-session,
disguised double extensions (`map.litematic.jar`), archives containing traversal
entries, malformed/zip-bomb archives (turned into findings, not crashes), and files
matching a pinned known-malicious hash.

## Explicitly out of scope

- Kernel/minifilter drivers, Java agents, or bytecode instrumentation.
- Cloud malware analysis, VirusTotal uploads, ML classification.
- Automatic deletion of files.
- Forge/NeoForge support (the core is designed to allow an adapter later).
- Generic packet interception for arbitrary mods.
- Any claim of guaranteed malware detection.

## Same-JVM limitations (read this)

The Fabric mod and a malicious mod share one JVM with **equal privileges**.
Therefore the Fabric mod **cannot**:

- Reliably contain, sandbox, or kill code that is already executing.
- Guarantee it sees a write before the writer also tampers with SecuroGuard.
- Trust its own in-memory state against a co-resident adversary that specifically
  targets it.

This is why the **Sentinel is the stronger boundary**: before launch, the malicious
JAR is inert bytes on disk. The Sentinel hashes and inspects it without ever giving
it a chance to run, and a launcher can **block launch** on a non-zero exit code.

## Race conditions and TOCTOU

- **WatchService races.** OS file events can be coalesced, delayed, or dropped
  (`OVERFLOW`). Mitigations: debounce/settle before hashing, full reconciliation on
  overflow, and a periodic reconciliation sweep to recover missed events.
- **Time-of-check/time-of-use.** A file can change between hashing and quarantine.
  Mitigation: quarantine re-hashes the destination and only deletes the original
  after byte-for-byte verification; a hash mismatch aborts and preserves the
  original. The runtime re-scans after any change so findings reflect current state.
- **Atomic moves into `mods`.** A rename-into-place appears as a single create of a
  complete file; the settle tracker handles it naturally.

## Attempts to disable SecuroGuard

A hostile mod in the same JVM could try to stop the monitor, delete the baseline,
or corrupt logs. SecuroGuard reduces but cannot eliminate this:

- The **baseline lives on disk** and is re-read each scan; a corrupt baseline is
  preserved and treated as "no trust", not silently trusted.
- The **Sentinel re-establishes ground truth** outside the game entirely — the
  recommended way to get a trustworthy verdict is a pre-launch Sentinel scan.
- Monitor failures are **reported**, not swallowed, so a killed monitor is visible.

If you need assurance that cannot be undermined by an already-running mod, run the
Sentinel before launch and gate on its exit code.

## Quarantine restore — a hostile/corrupt sidecar

The sidecar next to a quarantined file is untrusted data (it lives on disk and could
be edited by a hostile process). **No sidecar-controlled value may cause a write
outside the instance.** Restore therefore:

- Reconstructs the target as `gameDir + validatedRelativePath` and **never** uses the
  sidecar's `originalAbsolutePath`.
- Rejects absolute / drive-qualified / UNC / `..`-traversal relative paths, control
  characters, and anything that resolves outside `gameDir` after normalization.
- Requires a valid schema version, a non-empty id consistent with the
  `storedFileName`, a `storedFileName` that is a plain basename (no separators), a
  well-formed SHA-256, and a stored file whose size and hash match the sidecar.
- Refuses to follow a symlink masquerading as the stored file, refuses a restore
  target whose parent is missing or is a symlink/junction, and refuses to overwrite an
  existing target (via a create-only copy).
- Verifies the restored file's hash before deleting the quarantine copy, so **any
  failure preserves the quarantine copy and sidecar** for review.

**Residual TOCTOU.** The canonical link/containment checks and the create-only copy
are not a single atomic operation. A local attacker able to swap a parent directory
for a symlink in the microseconds between the check and the write could still redirect
a restore. Java NIO has no portable atomic "create-only, no-follow, contained" write;
we minimise the window and disclose the residual risk rather than implying it is
closed. On Windows, symlink/junction creation typically requires privilege, which
further narrows the window.

## Advisory feed integrity

Advisory data influences findings, so it must be trustworthy. The bundled feed is
trusted as part of the signed release artifact. Any non-bundled feed must pass
**Ed25519 verification against a pinned public key** (`VerifiedAdvisorySource`) before
it is parsed or applied — unverified bytes yield an empty feed. There is no unsigned
remote fetch in this release, so a network attacker cannot inject advisories.

## Signature files are not signer trust

A JAR containing `META-INF/*.RSA`/`.SF` merely *claims* to be signed. SecuroGuard
records that signature entries exist but **never** treats their presence as proof the
signature is valid or the signer is trusted (`signerTrustEstablished()` is always
false). Establishing real signer trust is out of scope for this release.
