# Third-Party Notices

SecuroGuard itself is licensed under the Apache License 2.0 (see `LICENSE` and
`NOTICE`). This document lists third-party components and their licenses, grouped by
how they relate to a SecuroGuard release. Where a license name is given it reflects
the license published by that project at the time of writing; always confirm against
the upstream project for the exact version you use.

## Bundled / physically distributed in a SecuroGuard artifact

These are included inside a downloadable SecuroGuard artifact:

| Component | Version | License | Where |
|---|---|---|---|
| Gson (`com.google.code.gson:gson`) | 2.11.0 | Apache-2.0 | Sentinel distribution (`lib/`) |
| Error Prone annotations (`com.google.errorprone:error_prone_annotations`) | 2.27.0 | Apache-2.0 | Sentinel distribution (`lib/`); transitive dependency of Gson |
| securoguard-core | (this project) | Apache-2.0 | nested in the Fabric mod jar (`META-INF/jars/`) and as the Sentinel's own code |

> The Fabric mod jar does **not** bundle Gson: at runtime it uses the copy of Gson
> that Minecraft already ships. Gson is only physically redistributed in the Sentinel
> ZIP/TAR distributions.

## Build- and test-only (not distributed to users)

Used only to compile or test SecuroGuard; not shipped in any user artifact:

| Component | License |
|---|---|
| JUnit 5 (`org.junit.jupiter:*`, `org.junit.platform:*`) | EPL-2.0 |
| Fabric Loom (Gradle plugin) | MIT |
| Gradle | Apache-2.0 |

## Runtime dependencies the user installs separately

Required to run the Fabric mod, but installed by the user (via a Minecraft launcher
and mod folder), not redistributed by SecuroGuard:

| Component | License | Notes |
|---|---|---|
| Minecraft: Java Edition | Proprietary (Mojang/Microsoft EULA) | Not distributed by SecuroGuard |
| Fabric Loader | Apache-2.0 | User-installed |
| Fabric API | Apache-2.0 | User-installed |
| Yarn mappings | CC0-1.0 | Build-time mappings; not shipped |
| Mod Menu (optional) | MIT | Optional; user-installed. Only its compile-time API is referenced. |

## Notes

- No third-party source code is copied into this repository; all dependencies are
  resolved by Gradle from their published coordinates.
- This file is provided for transparency. It is not legal advice, and it does not
  grant any rights beyond those in each component's own license.
