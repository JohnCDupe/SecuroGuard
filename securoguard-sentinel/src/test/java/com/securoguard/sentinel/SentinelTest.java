package com.securoguard.sentinel;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class SentinelTest {

    private record Result(int code, String out, String err) {
    }

    private Result run(String... argv) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        ByteArrayOutputStream e = new ByteArrayOutputStream();
        int code = new Sentinel(new PrintStream(o, true, StandardCharsets.UTF_8),
                new PrintStream(e, true, StandardCharsets.UTF_8)).run(argv);
        return new Result(code, o.toString(StandardCharsets.UTF_8), e.toString(StandardCharsets.UTF_8));
    }

    private Path jar(Path dir, String name, String modId) throws IOException {
        Files.createDirectories(dir);
        Path p = dir.resolve(name);
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("fabric.mod.json",
                ("{\"schemaVersion\":1,\"id\":\"" + modId + "\",\"version\":\"1.0.0\"}")
                        .getBytes(StandardCharsets.UTF_8));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bos)) {
            for (var en : entries.entrySet()) {
                zip.putNextEntry(new ZipEntry(en.getKey()));
                zip.write(en.getValue());
                zip.closeEntry();
            }
        }
        Files.write(p, bos.toByteArray());
        return p;
    }

    /** Writes a jar to an explicit path with a specific mod id and version. */
    private void writeModJar(Path file, String modId, String version) throws IOException {
        Files.createDirectories(file.getParent());
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bos)) {
            zip.putNextEntry(new ZipEntry("fabric.mod.json"));
            zip.write(("{\"schemaVersion\":1,\"id\":\"" + modId + "\",\"version\":\"" + version + "\"}")
                    .getBytes(StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        Files.write(file, bos.toByteArray());
    }

    @Test
    void missingGameDirIsConfigError() {
        assertEquals(ExitCode.CONFIG_ERROR, run("scan").code());
    }

    @Test
    void invalidMinSeverityIsConfigError(@TempDir Path game) {
        // Parsed before the monitor starts, so this returns immediately (no blocking).
        assertEquals(ExitCode.CONFIG_ERROR,
                run("watch", "--game-dir", game.toString(), "--min-severity", "bogus").code());
    }

    @Test
    void scanWarnsWhenMcVersionOmitted(@TempDir Path game) throws IOException {
        jar(game.resolve("mods"), "a.jar", "a");
        Result r = run("scan", "--game-dir", game.toString());
        assertTrue(r.err().contains("--mc-version not supplied"),
                "Sentinel must warn that coordinate advisory matching may be incomplete");
    }

    @Test
    void unknownCommandIsConfigError() {
        assertEquals(ExitCode.CONFIG_ERROR, run("frobnicate", "--game-dir", "x").code());
    }

    @Test
    void cleanInstanceScanIsOk(@TempDir Path game) throws IOException {
        jar(game.resolve("mods"), "sodium.jar", "sodium");
        // Approve first so the jar is trusted.
        assertEquals(ExitCode.OK, run("approve", "--game-dir", game.toString(), "--yes").code());
        Result scan = run("scan", "--game-dir", game.toString());
        assertEquals(ExitCode.OK, scan.code(), scan.out() + scan.err());
        assertTrue(scan.out().contains("Baseline: present"));
    }

    @Test
    void newUntrustedJarProducesWarningsExitCode(@TempDir Path game) throws IOException {
        jar(game.resolve("mods"), "sodium.jar", "sodium");
        run("approve", "--game-dir", game.toString(), "--yes");
        // Add a new jar after approval.
        jar(game.resolve("mods"), "sneaky.jar", "sneaky");
        Result scan = run("scan", "--game-dir", game.toString());
        assertEquals(ExitCode.WARNINGS, scan.code(), scan.out());
        assertTrue(scan.out().contains("SG-NEW-UNTRUSTED-JAR"));
    }

    @Test
    void knownMaliciousHashProducesCriticalExitCode(@TempDir Path game) throws IOException {
        Path mods = game.resolve("mods");
        Path malicious = jar(mods, "evil.jar", "evil");
        // Compute its hash and register it as known-malicious via config.
        String hash = com.securoguard.core.util.Hashing.sha256(malicious);
        Path config = game.resolve("config");
        Files.createDirectories(config);
        Files.writeString(config.resolve("securoguard.json"),
                "{\"knownMaliciousHashes\":[\"" + hash + "\"]}", StandardCharsets.UTF_8);

        Result scan = run("scan", "--game-dir", game.toString());
        assertEquals(ExitCode.CRITICAL, scan.code(), scan.out());
        assertTrue(scan.out().contains("SG-KNOWN-MALICIOUS-HASH"));
    }

    @Test
    void vulnerableModAdvisoryProducesWarningExitCode(@TempDir Path game) throws IOException {
        // An affected Litematica version on 1.21.11 (patched at 0.26.11).
        writeModJar(game.resolve("mods").resolve("litematica.jar"), "litematica", "0.26.10");
        run("approve", "--game-dir", game.toString(), "--yes");
        Result scan = run("scan", "--game-dir", game.toString(), "--mc-version", "1.21.11");
        assertEquals(ExitCode.WARNINGS, scan.code(), scan.out());
        assertTrue(scan.out().contains("SG-ADVISORY"));
    }

    @Test
    void approveRequiresYes(@TempDir Path game) throws IOException {
        jar(game.resolve("mods"), "a.jar", "a");
        assertEquals(ExitCode.CONFIG_ERROR, run("approve", "--game-dir", game.toString()).code());
    }

    @Test
    void statusReportsBaselineAndDoesNotChangeTrust(@TempDir Path game) throws IOException {
        jar(game.resolve("mods"), "a.jar", "a");
        Result before = run("status", "--game-dir", game.toString());
        assertEquals(ExitCode.OK, before.code());
        assertTrue(before.out().contains("Baseline: none"));
        // Still no baseline afterwards — status must not establish trust.
        Result after = run("status", "--game-dir", game.toString());
        assertTrue(after.out().contains("Baseline: none"));
    }

    @Test
    void quarantineAndRestoreViaCli(@TempDir Path game) throws IOException {
        Path mods = game.resolve("mods");
        Path evil = jar(mods, "evil.jar", "evil");
        Result q = run("quarantine", "--game-dir", game.toString(), "--file", evil.toString());
        assertEquals(ExitCode.OK, q.code(), q.err());
        assertFalse(Files.exists(evil), "file should be moved out of mods");

        // Extract the id from output ("  id=...").
        String id = q.out().lines().filter(l -> l.trim().startsWith("id="))
                .map(l -> l.trim().substring(3)).findFirst().orElseThrow();

        // Restore requires --yes.
        assertEquals(ExitCode.CONFIG_ERROR,
                run("restore", "--game-dir", game.toString(), "--item", id).code());
        Result r = run("restore", "--game-dir", game.toString(), "--item", id, "--yes");
        assertEquals(ExitCode.OK, r.code(), r.err());
        assertTrue(Files.exists(evil), "file restored to mods");
    }
}
