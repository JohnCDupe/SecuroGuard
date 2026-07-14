# Contributing to SecuroGuard

Thanks for your interest in improving SecuroGuard. This is a security-focused
project, so contributions are held to a careful standard — but newcomers are very
welcome, and small, well-tested changes are the easiest to review and merge.

## Before you start

- **Security issues do not go in public issues or pull requests.** See
  [SECURITY.md](SECURITY.md) for private reporting.
- Please open an issue to discuss larger changes before writing them, so we can
  agree on the approach.
- By contributing, you agree that your contributions are licensed under the
  project's [Apache License 2.0](LICENSE).

## Project layout

| Module | What it is |
|---|---|
| `securoguard-core` | Loader-neutral security engine (no Minecraft/Fabric dependencies). |
| `securoguard-sentinel` | External command-line scanner (pre-launch boundary). |
| `securoguard-fabric` | Client-side Fabric mod (runtime monitoring). |

Keep Minecraft/Fabric types out of `securoguard-core`.

## Building and testing

Requires JDK 21 (the build uses Gradle toolchains). Use the wrapper:

```bash
./gradlew build            # compile + all tests + assemble artifacts
./gradlew test             # tests only
./gradlew :securoguard-core:test --tests "*Advisory*"
```

Windows: use `gradlew.bat`.

## What we look for in a change

1. **Tests for every behavioral change.** Adversarial/regression tests are
   especially valued for the monitor, quarantine, advisory, and path-handling code.
2. **Do not weaken protections.** Containment, hashing, advisory verification,
   baseline trust, monitoring delivery guarantees, and quarantine safety must not be
   loosened. If a change touches these, explain the security reasoning.
3. **Never execute or load a scanned JAR's classes.** Inspection is metadata-only.
4. **No telemetry, analytics, accounts, network uploads of file contents, secrets,
   API keys, or bundled binaries** beyond what is already documented.
5. **Style:** match the surrounding code. An `.editorconfig` is provided; keep Java
   lines within ~120 columns, use 4-space indentation, and add focused comments for
   non-obvious security decisions.
6. Keep commits logical and messages descriptive.

## Pull requests

- Fill out the pull-request template.
- Ensure `./gradlew build` passes locally on Java 21.
- Note any behavior you could not verify (for example, GUI screens that need a
  running Minecraft client) rather than claiming it was tested.

## Reporting bugs and requesting features

Use the issue templates. For anything security-sensitive, use private reporting
instead — do **not** attach live malware, tokens, credentials, or private files.
