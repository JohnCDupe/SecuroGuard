package com.securoguard.core.jar;

import java.util.List;

/**
 * The subset of {@code fabric.mod.json} we surface. This is descriptive metadata
 * only; declaring an entrypoint here does not mean SecuroGuard runs it — it never
 * does. {@code declaredNestedJars} are the paths a mod says it bundles (the "jars"
 * array), which we cross-check against what the archive actually contains.
 */
public record ModMetadata(
        String modId,
        String name,
        String version,
        List<String> entrypoints,
        List<String> declaredNestedJars) {
}
