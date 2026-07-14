package com.securoguard.core.inventory;

import java.util.List;

/**
 * Loader-neutral descriptor of a mod the loader reported as installed/loaded. The
 * Fabric adapter builds these from {@code FabricLoader.getAllMods()} /
 * {@link ModContainer}; a future NeoForge adapter would build the same shape. The
 * core stays free of any loader dependency.
 *
 * @param modId       loader mod id
 * @param name        human name
 * @param version     declared version string
 * @param loader      loader name (e.g. "fabric") — used for advisory matching
 * @param originPaths absolute origin paths, if the origin maps to ordinary files
 *                    (a mod may have several; may be empty for synthetic mods)
 * @param nested      true if this is a nested/jar-in-jar mod, when determinable
 * @param synthetic   true if the mod has no ordinary on-disk file (built-in mods
 *                    like "minecraft"/"java", or origins on a non-default filesystem)
 */
public record InstalledMod(
        String modId,
        String name,
        String version,
        String loader,
        List<String> originPaths,
        boolean nested,
        boolean synthetic) {

    public InstalledMod {
        originPaths = originPaths == null ? List.of() : List.copyOf(originPaths);
    }
}
