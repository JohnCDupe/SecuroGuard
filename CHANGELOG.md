# Changelog

All notable changes to SecuroGuard are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Loader-neutral security engine (`securoguard-core`): instance paths, file
  inventory with SHA-256, versioned per-scope baselines, NIO `WatchService`-based
  runtime monitor, metadata-only JAR inspection with defensive limits, a composable
  rule engine, opt-in quarantine, and an Ed25519-verified advisory model.
- External Sentinel CLI (`securoguard-sentinel`) with `scan`, `status`, `approve`,
  `quarantine`, `restore`, and `watch`, plus documented exit codes for launcher
  pre-launch integration.
- Client-side Fabric mod (`securoguard-fabric`) for Minecraft 1.21.11: runtime
  monitoring, findings screen, confirmed quarantine, disconnect action, and a
  Mod Menu configuration screen.
- Bundled Litematica/Servux advisory data (separate per-mod, per-Minecraft-line
  advisories) for the 2026-07-06 arbitrary-file-write disclosure.
- Reproducible-where-possible archive settings, a `verifyReleaseArtifacts` task, and
  a `releaseChecksums` task that produces `SHA256SUMS.txt`.
- Community and project health files, CI (Ubuntu + Windows) with SHA-pinned actions,
  and a tag-triggered release workflow.

### Security

- Quarantine restore is containment-checked: no sidecar-controlled value can cause a
  write outside the configured instance.
- Quarantine is transactional: a durable transaction record makes any post-move
  failure a recoverable orphan; the source is never silently returned to `mods` and
  the only copy is never deleted. Symbolic-link sources are refused.
- Inventory scanning does not follow file symlinks/junctions to out-of-instance
  targets; such entries are reported as skipped.
- Monitor delivery is truthful: a change is only marked delivered when its listener
  callback returns normally; failures keep the change pending, retry with bounded
  backoff, and hold health `DEGRADED`. Lost watch registrations are detected and
  re-registered.
- Advisory matching never guesses: an unknown Minecraft version or loader yields no
  coordinate match and a single informational finding. A failed feed load/verify
  surfaces a degraded-protection finding rather than a silent "all clear".

[Unreleased]: https://keepachangelog.com/
