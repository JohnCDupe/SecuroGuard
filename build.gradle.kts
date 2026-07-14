// Root build for the SecuroGuard multi-project build.
// The root applies no plugins itself; each module configures its own toolchain
// so that Minecraft/Fabric concerns stay isolated in securoguard-fabric.

import java.security.MessageDigest
import java.util.zip.ZipFile

allprojects {
    group = property("group") as String
    version = property("version") as String
}

subprojects {
    repositories {
        mavenCentral()
    }
    // Reproducible archives where the toolchain permits: stable entry order and no
    // embedded file timestamps. NOTE: Fabric Loom's remapJar step performs its own
    // post-processing, so the remapped mod jar may still not be bit-for-bit
    // reproducible across environments — see docs and the reproducibility check.
    tasks.withType<org.gradle.api.tasks.bundling.AbstractArchiveTask>().configureEach {
        isPreserveFileTimestamps = false
        isReproducibleFileOrder = true
    }
}

// --- Release artifact tooling -------------------------------------------------
//
// The production artifacts are exactly:
//   * the remapped Fabric mod jar (NOT the -sources / -dev jars)
//   * the Sentinel distribution ZIP and TAR
// The tasks below depend on the precise producing tasks so they never run before
// the artifacts exist, and they fail loudly if an expected artifact is missing.

val fabricLibs = layout.projectDirectory.dir("securoguard-fabric/build/libs").asFile
val sentinelDist = layout.projectDirectory.dir("securoguard-sentinel/build/distributions").asFile
// Captured at configuration time (project scope), so they are safe to use in doLast.
val minecraftVersionProp = property("minecraftVersion") as String
val projectVersionProp = version.toString()

// Select the artifact for the CURRENT version by exact name, so stale outputs from a
// previous version in build/libs cannot be confused with the production artifact.
fun productionFabricJar(): File {
    val expected = "securoguard-$projectVersionProp+mc$minecraftVersionProp.jar"
    val f = File(fabricLibs, expected)
    require(f.exists()) { "Production Fabric jar not found: $expected (run :securoguard-fabric:remapJar)" }
    return f
}

fun sentinelArchive(ext: String): File {
    val expected = "securoguard-$projectVersionProp$ext"
    val f = File(sentinelDist, expected)
    require(f.exists()) { "Sentinel artifact not found: $expected (run :securoguard-sentinel:dist)" }
    return f
}

fun releaseArtifacts(): List<File> =
    listOf(productionFabricJar(), sentinelArchive(".zip"), sentinelArchive(".tar")).sortedBy { it.name }

/** Streams a file through SHA-256 (never loads the whole artifact into memory). */
fun sha256(file: File): String {
    val md = MessageDigest.getInstance("SHA-256")
    file.inputStream().buffered().use { input ->
        val buf = ByteArray(64 * 1024)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            md.update(buf, 0, n)
        }
    }
    return java.util.HexFormat.of().formatHex(md.digest())
}

fun zipEntryNames(archive: File): Set<String> =
    ZipFile(archive).use { zf -> zf.entries().asSequence().map { it.name }.toSet() }

fun readZipEntry(archive: File, name: String): String? =
    ZipFile(archive).use { zf ->
        val e = zf.getEntry(name) ?: return null
        zf.getInputStream(e).readBytes().toString(Charsets.UTF_8)
    }

// Collect entry paths from any Gradle FileTree (e.g. project.tarTree(...) for a TAR,
// which lazily unpacks to a temp dir on visit — it never executes archive contents).
fun entryNamesOf(tree: org.gradle.api.file.FileTree): Set<String> {
    val names = sortedSetOf<String>()
    tree.visit { names.add(relativePath.pathString) }
    return names
}

// Shared structural check applied INDEPENDENTLY to the Sentinel ZIP and TAR. Fails if
// the archive is missing legal files, the launcher scripts, the SecuroGuard core /
// Sentinel libraries for this version, or Gson.
fun requireSentinelEntries(entries: Set<String>, label: String, projectVersion: String) {
    listOf("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md").forEach { legal ->
        require(entries.any { it.endsWith("/$legal") || it == legal }) {
            "Sentinel $label is missing $legal (has: ${entries.take(20)})"
        }
    }
    require(entries.any { it.endsWith("/bin/securoguard") }) {
        "Sentinel $label is missing the launcher script bin/securoguard"
    }
    require(entries.any { it.endsWith("/bin/securoguard.bat") }) {
        "Sentinel $label is missing the launcher script bin/securoguard.bat"
    }
    require(entries.any { Regex("/lib/securoguard-core-[^/]*\\.jar$").containsMatchIn(it) && it.contains(projectVersion) }) {
        "Sentinel $label must bundle securoguard-core-$projectVersion.jar in lib/"
    }
    require(entries.any { Regex("/lib/securoguard-sentinel-[^/]*\\.jar$").containsMatchIn(it) && it.contains(projectVersion) }) {
        "Sentinel $label must bundle securoguard-sentinel-$projectVersion.jar in lib/"
    }
    require(entries.any { it.contains("/lib/gson-") && it.endsWith(".jar") }) {
        "Sentinel $label must bundle gson in lib/"
    }
}

// Verifies the production artifacts are well-formed: correct version metadata and the
// required legal files packaged. Fails the build if anything is missing.
tasks.register("verifyReleaseArtifacts") {
    group = "verification"
    description = "Opens the release artifacts and asserts version metadata and legal files."
    dependsOn(":securoguard-fabric:remapJar", ":securoguard-sentinel:distZip", ":securoguard-sentinel:distTar")
    doLast {
        val projectVersion = projectVersionProp
        val expectedModVersion = "$projectVersion+mc$minecraftVersionProp"

        // --- Fabric mod jar ---
        val fabricJar = productionFabricJar()
        val fabricEntries = zipEntryNames(fabricJar)
        listOf("META-INF/LICENSE", "META-INF/NOTICE", "fabric.mod.json").forEach {
            require(it in fabricEntries) { "Fabric jar is missing $it (has: ${fabricEntries.take(20)})" }
        }
        val fmj = readZipEntry(fabricJar, "fabric.mod.json")!!
        val versionInFmj = Regex("\"version\"\\s*:\\s*\"([^\"]+)\"").find(fmj)?.groupValues?.get(1)
        require(versionInFmj == expectedModVersion) {
            "fabric.mod.json version '$versionInFmj' != expected '$expectedModVersion'"
        }
        if (projectVersion.contains("-")) {
            require(versionInFmj!!.contains("-")) { "A prerelease build must not present a stable version" }
        }
        val nestedCore = fabricEntries.firstOrNull { it.startsWith("META-INF/jars/securoguard-core") }
        require(nestedCore != null) { "Fabric jar must bundle the nested securoguard-core jar" }
        require(nestedCore!!.contains(projectVersion)) {
            "Nested core jar '$nestedCore' must carry the project version '$projectVersion'"
        }

        // --- Sentinel distributions: ZIP and TAR inspected INDEPENDENTLY ---
        // The ZIP is read with java.util.zip; the TAR is read via Gradle's tarTree.
        // No assumption is made that one archive mirrors the other.
        val zipArchive = sentinelArchive(".zip")
        requireSentinelEntries(zipEntryNames(zipArchive), "ZIP", projectVersion)

        val tarArchive = sentinelArchive(".tar")
        requireSentinelEntries(entryNamesOf(project.tarTree(tarArchive)), "TAR", projectVersion)

        logger.lifecycle("verifyReleaseArtifacts: OK (mod version $expectedModVersion; ZIP and TAR verified independently; legal files, launcher scripts, core/sentinel libs and gson present)")
    }
}

// Deterministic SHA-256 checksums for the verified release artifacts. Writes one
// <artifact>.sha256 per file plus a single SHA256SUMS.txt in the repository root.
tasks.register("releaseChecksums") {
    group = "distribution"
    description = "Verifies and checksums the production release artifacts."
    dependsOn("verifyReleaseArtifacts")
    doLast {
        val artifacts = releaseArtifacts()
        val sumsLines = StringBuilder()
        artifacts.forEach { f ->
            val hex = sha256(f)
            File(f.parentFile, f.name + ".sha256").writeText("$hex  ${f.name}\n")
            sumsLines.append("$hex  ${f.name}\n")
            logger.lifecycle("$hex  ${f.name}")
        }
        val sums = layout.projectDirectory.file("SHA256SUMS.txt").asFile
        sums.writeText(sumsLines.toString())
        logger.lifecycle("Wrote ${sums.name} for ${artifacts.size} artifact(s).")
        logger.lifecycle("Note: a checksum verifies file INTEGRITY only; it does not prove publisher authenticity.")
    }
}
