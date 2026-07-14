package com.securoguard.core.instance;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Pure validation-logic coverage for {@link PathSecurity}. This guarantees the
 * restore/containment guards are tested even on platforms where the integration
 * tests must skip real symlink creation.
 */
class PathSecurityTest {

    private final Path root = Path.of("C:/instance").toAbsolutePath();

    @Test
    void acceptsSafeRelativePaths() {
        assertDoesNotThrow(() -> PathSecurity.resolveContainedRelative(root, "mods/a.jar"));
        assertDoesNotThrow(() -> PathSecurity.resolveContainedRelative(root, "config/sub/x.json"));
        Path resolved = PathSecurity.resolveContainedRelative(root, "mods/a.jar");
        assertTrue(resolved.startsWith(root.toAbsolutePath().normalize()));
    }

    @Test
    void rejectsAbsoluteDriveUncAndTraversal() {
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "/etc/passwd"));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "\\windows\\x"));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "C:\\x"));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "C:x"));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "//host/share/x"));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "mods/../../x"));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "../x"));
    }

    @Test
    void rejectsNullBlankAndControlChars() {
        String withNull = "mods/a" + (char) 0 + "b.jar";
        String withTab = "mods/a" + (char) 9 + "b.jar";
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, null));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, "   "));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, withNull));
        assertThrows(SecurityException.class, () -> PathSecurity.resolveContainedRelative(root, withTab));
    }

    @Test
    void basenameValidation() {
        assertTrue(PathSecurity.isBasename("file.quarantined"));
        assertTrue(PathSecurity.isBasename("123-abc__evil.jar.quarantined"));
        assertFalse(PathSecurity.isBasename("sub/file.quarantined"));
        assertFalse(PathSecurity.isBasename("sub\\file.quarantined"));
        assertFalse(PathSecurity.isBasename(".."));
        assertFalse(PathSecurity.isBasename("."));
        assertFalse(PathSecurity.isBasename(""));
        assertFalse(PathSecurity.isBasename(null));
        assertFalse(PathSecurity.isBasename("C:evil"));
    }

    @Test
    void redirectedAncestorFalseForPlainContainedPath(@TempDir Path realRoot) {
        // With no links anywhere, a contained target has no redirected ancestor.
        Path target = realRoot.resolve("mods").resolve("a.jar");
        assertFalse(PathSecurity.hasRedirectedAncestor(realRoot, target));
    }

    @Test
    void regularFileIsNotClassifiedAsRedirect(@TempDir Path dir) throws IOException {
        Path regularFile = Files.writeString(dir.resolve("ordinary.jar"), "contents");
        assertFalse(PathSecurity.isLinkOrRedirect(regularFile));
    }
}
