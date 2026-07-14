# Security Policy

## Reporting a vulnerability

**Please report security issues privately.** Do **not** open a public issue for a
suspected vulnerability in SecuroGuard.

- Use GitHub's **private vulnerability reporting**: on the repository, open the
  *Security* tab and choose **"Report a vulnerability"**. This creates a private
  advisory visible only to you and the maintainers. You can open the private form
  directly at <https://github.com/JohnCDupe/SecuroGuard/security/advisories/new>.

Include: affected version/commit, a clear description, and minimal reproduction
steps. Reports will be acknowledged promptly and a fix and disclosure timeline
coordinated with you.

## Do NOT include live malware or secrets in reports

- **Never attach live malware** (or a working exploit payload) to a public issue,
  a pull request, or an unencrypted email. If a sample is essential, coordinate a
  secure channel with the maintainers first and share **hashes**, not executables,
  wherever possible.
- **Never submit credentials or session tokens.** Do not paste Minecraft access
  tokens, `launcher_accounts.json`, authorization headers, or the contents of
  credential files. SecuroGuard does not intentionally search for or parse
  credentials, tokens, or launcher account data; files inside a selected scan scope
  may be read for hashing and their paths or metadata may appear in local findings
  or logs, but file contents are not uploaded — please keep secrets out of reports
  too.
- Redact absolute/home paths where they are not relevant (the Sentinel's
  `--redact` flag helps produce shareable output).

## Scope

In scope: bugs in SecuroGuard that could cause it to miss the threats it claims to
detect, to damage or delete user files, to execute inspected content, to leak
private data (server addresses, tokens, telemetry), or to be trivially disabled in
ways beyond the documented same-JVM limitation.

Out of scope: the inherent same-JVM limitation (a mod already executing cannot be
reliably contained — this is documented, not a bug), and threats explicitly listed
as out of scope in [docs/threat-model.md](docs/threat-model.md).

## Data handling notes

- SecuroGuard stores only SHA-256 hashes and file metadata. It computes SHA-512
  **only** for the optional, hash-only Modrinth lookup, and uploads no file contents.
- Advisory data is only applied from the bundled feed or after Ed25519 verification
  against a pinned key; there is no unsigned remote fetch.
- Quarantine restore is containment-checked and will not write outside the configured
  instance from any sidecar field. A documented residual symlink/junction TOCTOU
  window exists (see [docs/threat-model.md](docs/threat-model.md)); reports that
  narrow or close it are welcome.

## Supported versions

This project is pre-release (`0.1.x`). Security fixes target the **latest** release/commit
on the default branch. There is no long-term support branch yet; once a stable
`1.0` line exists, this section will define a support window.

| Version | Supported |
|---|---|
| latest `main` / `0.1.x` | ✅ |
| older commits | ❌ (please update) |
