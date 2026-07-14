package com.securoguard.fabric;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Verifies the mod's version identity is honest: the processed {@code fabric.mod.json}
 * must carry the full project version (including any {@code -SNAPSHOT}/prerelease) with
 * the Minecraft build appended as SemVer build metadata. A development build must never
 * present a stable-looking version.
 */
class FabricMetadataTest {

    /** The processed manifest lives here after {@code processResources} runs. */
    private static final Path PROCESSED = Path.of("build", "resources", "main", "fabric.mod.json");
    private static final Path ROOT_PROPS = Path.of("..", "gradle.properties");

    private static String prop(Map<String, String> props, String key) {
        String v = props.get(key);
        assertNotNull(v, "gradle.properties missing '" + key + "'");
        return v;
    }

    private static Map<String, String> readProps(Path p) throws IOException {
        var map = new java.util.HashMap<String, String>();
        for (String line : Files.readAllLines(p, StandardCharsets.UTF_8)) {
            String s = line.trim();
            if (s.isEmpty() || s.startsWith("#")) {
                continue;
            }
            int eq = s.indexOf('=');
            if (eq > 0) {
                map.put(s.substring(0, eq).trim(), s.substring(eq + 1).trim());
            }
        }
        return map;
    }

    @Test
    void processedManifestVersionMatchesRootAndMarksPrerelease() throws IOException {
        assertTrue(Files.exists(PROCESSED),
                "processed fabric.mod.json not found (run processResources); path=" + PROCESSED.toAbsolutePath());
        Map<String, String> props = readProps(ROOT_PROPS);
        String rootVersion = prop(props, "version");
        String mcVersion = prop(props, "minecraftVersion");

        JsonObject fmj = JsonParser.parseString(
                Files.readString(PROCESSED, StandardCharsets.UTF_8)).getAsJsonObject();
        String modVersion = fmj.get("version").getAsString();

        // Must be exactly the root version plus the Minecraft build metadata.
        assertEquals(rootVersion + "+mc" + mcVersion, modVersion,
                "mod version must preserve the full project version and append the MC build");

        // A SNAPSHOT/prerelease must be preserved — never masquerade as stable.
        if (rootVersion.contains("-")) {
            String prerelease = rootVersion.substring(rootVersion.indexOf('-') + 1);
            assertTrue(modVersion.contains("-" + prerelease),
                    "prerelease qualifier '" + prerelease + "' must survive into the mod version");
        }

        // Minecraft compatibility metadata stays correct.
        JsonObject depends = fmj.getAsJsonObject("depends");
        assertNotNull(depends, "fabric.mod.json must declare dependencies");
        assertTrue(depends.has("minecraft"), "must declare a minecraft dependency");
        assertTrue(depends.get("minecraft").getAsString().contains("1.21.11"),
                "minecraft dependency should target the supported line");

        // Published metadata must point users to the canonical project, source, and
        // issue tracker rather than a placeholder or a local development location.
        JsonObject contact = fmj.getAsJsonObject("contact");
        assertNotNull(contact, "fabric.mod.json must declare project contact links");
        assertEquals("https://github.com/JohnCDupe/SecuroGuard",
                contact.get("homepage").getAsString());
        assertEquals("https://github.com/JohnCDupe/SecuroGuard",
                contact.get("sources").getAsString());
        assertEquals("https://github.com/JohnCDupe/SecuroGuard/issues",
                contact.get("issues").getAsString());
    }

    @Test
    void versionIsValidSemverWithBuildMetadata() throws IOException {
        Map<String, String> props = readProps(ROOT_PROPS);
        String expected = prop(props, "version") + "+mc" + prop(props, "minecraftVersion");
        // MAJOR.MINOR.PATCH(-prerelease)?(+build)? — build metadata present and last.
        Pattern semver = Pattern.compile(
                "^\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?\\+[0-9A-Za-z.-]+$");
        Matcher m = semver.matcher(expected);
        assertTrue(m.matches(), "derived mod version must be valid SemVer: " + expected);
        assertTrue(expected.indexOf('+') > expected.indexOf('-') || !expected.contains("-"),
                "build metadata (+) must follow any prerelease (-)");
    }
}
