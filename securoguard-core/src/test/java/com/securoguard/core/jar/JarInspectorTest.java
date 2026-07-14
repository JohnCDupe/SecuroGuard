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

class JarInspectorTest {

    @Test
    void detectsDisguisedDoubleExtension() {
        assertTrue(JarInspector.hasDisguisedDoubleExtension("cool.litematic.jar"));
        assertTrue(JarInspector.hasDisguisedDoubleExtension("photo.png.jar"));
        assertTrue(JarInspector.hasDisguisedDoubleExtension("installer.exe.zip"));
        // Legitimate names must not be flagged.
        assertFalse(JarInspector.hasDisguisedDoubleExtension("sodium-fabric-0.6.0.jar"));
        assertFalse(JarInspector.hasDisguisedDoubleExtension("mymod.jar"));
    }

    @Test
    void parsesFabricMetadataAndFlagsDoubleExtension(@TempDir Path dir) throws IOException {
        Path jar = TestArchives.writeFile(dir, "example.litematic.jar",
                TestArchives.fabricModJar("examplemod", "1.2.3"));
        JarInspectionResult r = new JarInspector().inspect(jar);

        assertTrue(r.structurallyValidZip());
        assertTrue(r.modMetadata().isPresent());
        assertEquals("examplemod", r.modMetadata().get().modId());
        assertEquals("1.2.3", r.modMetadata().get().version());
        assertTrue(r.modMetadata().get().entrypoints().contains("client"));
        assertTrue(r.doubleExtension(), "example.litematic.jar is a disguised double extension");
    }

    @Test
    void reportsTraversalEntryNamesWithoutExtracting(@TempDir Path dir) throws IOException {
        Path jar = TestArchives.writeFile(dir, "traversal.jar", TestArchives.traversalZip());
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertFalse(r.traversalEntryNames().isEmpty(), "should flag ../ entries");
        assertTrue(r.traversalEntryNames().stream().anyMatch(n -> n.contains("..")));
    }

    @Test
    void malformedArchiveBecomesProblemNotException(@TempDir Path dir) throws IOException {
        // A .jar whose bytes are not a valid zip.
        Path jar = TestArchives.writeFile(dir, "broken.jar", "this is not a zip".getBytes(StandardCharsets.UTF_8));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertFalse(r.structurallyValidZip());
        assertFalse(r.problems().isEmpty(), "malformed archive should record a problem, not throw");
    }

    @Test
    void zipBombTrippedByCompressionRatioLimit(@TempDir Path dir) throws IOException {
        // 8 MB of zeros compresses to a few KB -> ratio far exceeds the default limit.
        Path jar = TestArchives.writeFile(dir, "bomb.jar", TestArchives.compressibleZip(8 * 1024 * 1024));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.limitExceeded(), "high compression ratio must trip a limit");
    }

    @Test
    void uncompressedByteLimitStopsInspection(@TempDir Path dir) throws IOException {
        // Tiny uncompressed cap so even a modest archive trips it deterministically.
        JarInspectionLimits tight = new JarInspectionLimits(
                256L * 1024 * 1024, 50_000, 4096, 100000, 3, 1024, 15_000, 128L * 1024 * 1024);
        Path jar = TestArchives.writeFile(dir, "big.jar", TestArchives.compressibleZip(1024 * 1024));
        JarInspectionResult r = new JarInspector(tight).inspect(jar);
        assertTrue(r.limitExceeded());
    }

    @Test
    void nestedJarDepthIsBounded(@TempDir Path dir) throws IOException {
        // 5 levels of nesting, but the default depth limit is 3.
        Path jar = TestArchives.writeFile(dir, "nested.jar", TestArchives.nestedJars(5));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.maxNestedDepthSeen() <= 3, "recursion must stop at the depth limit; was "
                + r.maxNestedDepthSeen());
    }

    @Test
    void detectsSignatureEntries(@TempDir Path dir) throws IOException {
        Map<String, byte[]> entries = new LinkedHashMap<>();
        entries.put("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n".getBytes(StandardCharsets.UTF_8));
        entries.put("META-INF/CERT.RSA", new byte[]{1, 2, 3});
        entries.put("Main.class", new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE});
        Path jar = TestArchives.writeFile(dir, "signed.jar", TestArchives.zipBytes(entries));
        JarInspectionResult r = new JarInspector().inspect(jar);
        assertTrue(r.hasSignatureEntries());
        assertFalse(r.manifestAttributes().isEmpty());
    }
}
