package com.securoguard.core.jar;

import com.securoguard.core.testutil.TestArchives;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Regression tests for the archive-inspector correctness fixes (R8).
 */
class JarInspectorCorrectnessTest {

    private static final long BIG = 256L * 1024 * 1024;

    @Test
    void corruptedEntryDataIsMalformedAndNotStructurallyValid(@TempDir Path dir) throws IOException {
        byte[] full = TestArchives.fabricModJar("corrupt", "1.0.0");
        // Corrupt bytes well inside the first entry's DEFLATE data (after the 30-byte
        // local header + the "fabric.mod.json" name), so inflation / CRC fails and
        // ZipInputStream reports an error rather than a clean end-of-stream.
        byte[] bad = full.clone();
        for (int i = 46; i < Math.min(bad.length - 30, 80); i++) {
            bad[i] ^= 0xFF;
        }
        Path jar = TestArchives.writeFile(dir, "corrupt.jar", bad);
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertFalse(r.structurallyValidZip(), "a mid-stream read failure must not be 'valid'");
        assertTrue(r.isMalformed(), "should be categorised MALFORMED");
        assertTrue(r.issues().contains(ArchiveIssue.MALFORMED));
    }

    @Test
    void perLevelCompressionRatioCatchesANestedBomb(@TempDir Path dir) throws IOException {
        // A benign outer jar that bundles a highly compressible inner jar.
        byte[] innerBomb = TestArchives.compressibleZip(8 * 1024 * 1024);
        Map<String, byte[]> outer = new LinkedHashMap<>();
        outer.put("fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"outer\",\"version\":\"1\"}"
                .getBytes(StandardCharsets.UTF_8));
        outer.put("META-INF/jars/inner.jar", innerBomb);
        Path jar = TestArchives.writeFile(dir, "outer.jar", TestArchives.zipBytes(outer));

        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.limitExceeded(), "nested bomb must trip the ratio limit at its own level");
        assertTrue(r.issues().contains(ArchiveIssue.LIMIT_EXCEEDED));
    }

    @Test
    void benignNestedJarsDoNotTripRatio(@TempDir Path dir) throws IOException {
        // Two levels of ordinary (incompressible-ish) jars should not be flagged.
        Path jar = TestArchives.writeFile(dir, "nested.jar", TestArchives.nestedJars(2));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertFalse(r.limitExceeded(), "benign nesting must not be a false positive");
        assertTrue(r.structurallyValidZip());
    }

    @Test
    void inspectionDeadlineIsEnforced(@TempDir Path dir) throws IOException {
        // Zero time budget: inspection must stop and flag a limit rather than proceed.
        JarInspectionLimits noTime = new JarInspectionLimits(
                BIG, 50_000, 1024L * 1024 * 1024, 200, 3, 4 * 1024 * 1024, 0, 128L * 1024 * 1024);
        Path jar = TestArchives.writeFile(dir, "slow.jar", TestArchives.compressibleZip(2 * 1024 * 1024));
        JarInspectionResult r = new JarInspector(noTime).inspect(jar);
        assertTrue(r.limitExceeded());
        assertTrue(r.problems().stream().anyMatch(p -> p.toLowerCase().contains("time budget")));
    }

    @Test
    void cumulativeNestedMemoryBudgetIsEnforced(@TempDir Path dir) throws IOException {
        // A tiny cumulative budget: the first nested jar already exceeds it.
        JarInspectionLimits tinyMem = new JarInspectionLimits(
                BIG, 50_000, 1024L * 1024 * 1024, 200, 3, 4 * 1024 * 1024, 15_000, 64);
        Path jar = TestArchives.writeFile(dir, "nested.jar", TestArchives.nestedJars(2));
        JarInspectionResult r = new JarInspector(tinyMem).inspect(jar);
        assertTrue(r.limitExceeded());
        assertTrue(r.problems().stream().anyMatch(p -> p.toLowerCase().contains("memory budget")));
    }

    @Test
    void distinctIssueCategoriesAreReported(@TempDir Path dir) throws IOException {
        Path traversal = TestArchives.writeFile(dir, "trav.jar", TestArchives.traversalZip());
        JarInspectionResult tr = new JarInspector().inspect(traversal);
        assertTrue(tr.hasTraversalEntries());
        assertTrue(tr.issues().contains(ArchiveIssue.TRAVERSAL_ENTRY));
        assertFalse(tr.issues().contains(ArchiveIssue.MALFORMED));
    }

    @Test
    void declaredNestedJarMissingIsReported(@TempDir Path dir) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("fabric.mod.json", ("{\"schemaVersion\":1,\"id\":\"m\",\"version\":\"1\","
                + "\"jars\":[{\"file\":\"META-INF/jars/missing.jar\"}]}").getBytes(StandardCharsets.UTF_8));
        Path jar = TestArchives.writeFile(dir, "declares.jar", TestArchives.zipBytes(entries));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.problems().stream().anyMatch(p -> p.contains("Declared nested jar not present")));
    }

    @Test
    void declaredNestedJarTraversalIsFlagged(@TempDir Path dir) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("fabric.mod.json", ("{\"schemaVersion\":1,\"id\":\"m\",\"version\":\"1\","
                + "\"jars\":[{\"file\":\"../evil.jar\"}]}").getBytes(StandardCharsets.UTF_8));
        Path jar = TestArchives.writeFile(dir, "declares2.jar", TestArchives.zipBytes(entries));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.hasTraversalEntries(), "a declared traversal path must be flagged");
    }

    @Test
    void signaturePresenceDoesNotEstablishSignerTrust(@TempDir Path dir) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n".getBytes(StandardCharsets.UTF_8));
        entries.put("META-INF/CERT.RSA", new byte[]{1, 2, 3});
        entries.put("Main.class", new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        Path jar = TestArchives.writeFile(dir, "signed.jar", TestArchives.zipBytes(entries));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.hasSignatureEntries());
        assertFalse(r.signerTrustEstablished(), "presence of a .RSA file is not signer trust");
    }
}
