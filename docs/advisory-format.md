# SecuroGuard Advisory Feed Format

Advisories let SecuroGuard flag known-vulnerable mod versions and known-bad hashes.
**Obtaining a feed is deliberately separate from trusting it.** There is no
unsigned remote fetch in this release: the only feeds that can be applied are the
bundled one and any bytes that pass Ed25519 verification.

## How a feed reaches a scan (`AdvisorySource`)

`ScanService` consumes an `AdvisorySource`, never a raw feed:

- **`BundledAdvisorySource`** — the feed shipped inside the jar. Trusted because it
  is part of the (release-signed) artifact.
- **`VerifiedAdvisorySource`** — raw feed bytes + a detached Ed25519 signature +
  the pinned public key. It yields the parsed feed **only if the signature
  verifies**; otherwise it yields an empty feed. Unverified bytes are never applied.

Both the Sentinel and the Fabric mod use `BundledAdvisorySource` today.

## Feed JSON

```json
{
  "schemaVersion": 1,
  "generatedAtMillis": 1782864000000,
  "advisories": [
    {
      "id": "SG-ADV-2026-07-LITEMATICA-1.21.11",
      "modIds": ["litematica"],
      "loader": "fabric",
      "minecraftRange": { "introduced": "1.21.11", "fixed": "1.21.12" },
      "affectedRanges": [ { "introduced": null, "fixed": "0.26.11" } ],
      "fixedVersions": ["0.26.11"],
      "severity": "HIGH",
      "references": ["https://github.com/maruohon/litematica", "https://github.com/maruohon/litematica/releases"],
      "knownHashes": [],
      "publishedAtMillis": 1782864000000,
      "updatedAtMillis": 1782864000000
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `modIds` | Affected mod ids. Empty ⇒ hash-only advisory (not coordinate-scoped). |
| `loader` | Loader name; blank/null ⇒ any loader. |
| `minecraftRange` | Affected Minecraft version range, half-open. Null ⇒ any. |
| `affectedRanges` | Affected mod-version ranges, OR-combined. Empty ⇒ any version. |
| `fixedVersions` | Informational: versions that resolve the issue. |
| `severity` | `INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL` — becomes the finding severity. |
| `knownHashes` | SHA-256 (lowercase hex) known to be affected. Strongest match. |

Ranges are **half-open**: `introduced <= v < fixed`; either bound may be null.
Version comparison is numeric per dotted component, ignores `+build` metadata, and
ranks a `-prerelease` below the same release. Matching never throws on an odd
version string — it degrades to a safe non-match.

## Matching (`AdvisoryMatcher`)

1. **Hash match** — the file's SHA-256 is in `knownHashes` (version-independent).
2. **Coordinate match** — `modId` listed AND loader compatible AND Minecraft version
   in `minecraftRange` AND mod version within some `affectedRanges`.

In a scan, mod coordinates come from the loader (Fabric's `getAllMods()`), or — for
the pre-launch Sentinel — from each jar's `fabric.mod.json`. Matches become
`SG-ADVISORY` findings whose evidence carries the advisory id, installed version,
affected range, fixed version and references.

### No guessing when a coordinate is unknown

If an advisory constrains the **loader** or **Minecraft version** and the query does
not supply that coordinate, coordinate matching does **not** occur — SecuroGuard
never matches a mod against unrelated Minecraft-line advisories just because the
version was unknown. Such cases are reported once per scan as a single LOW
`SG-ADVISORY-INCOMPLETE` finding naming the missing coordinate (not one per
advisory). Malformed versions are safe non-matches (never treated as `0`), and
prerelease identifiers are compared numerically (`sakura.4 < sakura.10 < 0.22.2`).

### Known vs conservative lower bounds

Each advisory's `affectedRanges.introduced` marks the first vulnerable version:

- Where the maintainer's **introduction boundary is known** (Litematica on MC
  1.21–1.21.5), it is set, so a release **before** the vulnerable feature is *not*
  flagged (e.g. Litematica `0.19.59` on MC 1.21 is safe; `0.19.60` is the first
  affected).
- Where an authoritative introduction boundary is **not** available (Litematica on
  MC 1.21.6+ and **all** Servux lines), the lower bound is left **unbounded**. This
  is deliberately **conservative**: any version below the fixed version is flagged,
  which may over-flag a pre-feature release. We do not invent a boundary.

## Litematica / Servux (disclosed 2026-07-06)

Litematica and Servux are **separate advisories** (nine each, one per Minecraft
line) because their version numbers and patched boundaries differ. A Litematica
advisory lists only `litematica`; a Servux advisory lists only `servux`.

| Minecraft line | Litematica fixed | Litematica introduced | Servux fixed | Servux introduced |
|---|---|---|---|---|
| 1.21 – 1.21.1 | 0.19.61 | 0.19.60 | 0.3.17 | *(unbounded)* |
| 1.21.2 – 1.21.3 | 0.20.9 | 0.20.8 | 0.4.8 | *(unbounded)* |
| 1.21.4 | 0.21.7 | 0.21.6 | 0.5.7 | *(unbounded)* |
| 1.21.5 | 0.22.5 | 0.22.2-sakura.4 | 0.6.4 | *(unbounded)* |
| 1.21.6 – 1.21.8 | 0.23.7 | *(unbounded)* | 0.7.7 | *(unbounded)* |
| 1.21.9 – 1.21.10 | 0.24.8 | *(unbounded)* | 0.8.7 | *(unbounded)* |
| 1.21.11 | 0.26.11 | *(unbounded)* | 0.9.5 | *(unbounded)* |
| 26.1.x | 0.27.9 | *(unbounded)* | 0.10.4 | *(unbounded)* |
| 26.2 | 0.28.3 | *(unbounded)* | 0.11.2 | *(unbounded)* |

Vulnerability: a path-traversal in the schematic/file transfer allows a server to
write an arbitrary file (e.g. a JAR into `mods/`) that executes on a later launch.
Disclosure date **2026-07-06**. **No CVE/GHSA identifier is asserted** (none was
minted for this maintainer disclosure). References point to the maintainer repos,
their release pages, and the public security write-up. If you find a discrepancy in
these versions, please open an issue (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## Signature verification (Ed25519)

A production feed is detached-signed with Ed25519 over the exact feed bytes.
`AdvisoryFeedVerifier.verify(feedBytes, signature, pinnedPublicKey)` returns true
only if the signature is valid for those bytes under the pinned key. Verification is
**fail-closed**. Ed25519 is provided by the JDK (15+), so no third-party crypto
dependency is required. The public key is X.509 (SubjectPublicKeyInfo), supplied as
DER or base64.

## Planned signed remote feed (next milestone — not in this release)

1. Maintainers publish `feed.json` + a detached `feed.json.sig` (Ed25519) at a stable
   HTTPS URL.
2. Clients fetch both, **verify against the pinned public key**, and only then parse
   (via `VerifiedAdvisorySource`) — download is always separate from trust.
3. **Key rotation**: ship a new pinned key in a signed client release; overlap old and
   new keys for a transition window; a feed is accepted if it verifies under any
   currently-pinned key.
4. Feeds carry `generatedAtMillis`; clients reject a feed older than the last accepted
   one (rollback protection).
