package com.securoguard.fabric;

import com.securoguard.core.inventory.InstalledMod;

import net.fabricmc.loader.api.FabricLoader;
import net.fabricmc.loader.api.ModContainer;
import net.fabricmc.loader.api.metadata.ModMetadata;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Loader-specific view of what Fabric actually loaded, converted into
 * loader-neutral {@link InstalledMod} descriptors for securoguard-core. This is the
 * "Minecraft-aware runtime context" the Fabric side contributes: which on-disk
 * JARs correspond to loaded mods, sourced from {@link ModContainer#getOrigin()}
 * rather than guessed from the filesystem.
 */
public final class FabricModInventory {

    private FabricModInventory() {
    }

    /** Builds descriptors for every mod Fabric reports as loaded. */
    public static List<InstalledMod> loadedMods() {
        List<InstalledMod> out = new ArrayList<>();
        for (ModContainer mod : FabricLoader.getInstance().getAllMods()) {
            ModMetadata meta = mod.getMetadata();
            List<String> origins = new ArrayList<>();
            for (Path p : mod.getOrigin().getPaths()) {
                try {
                    origins.add(p.toAbsolutePath().normalize().toString());
                } catch (RuntimeException e) {
                    // Origin not on the default filesystem (jar-in-jar); skip that path.
                }
            }
            boolean nested = mod.getContainingMod().isPresent();
            // Synthetic: built-in mods (minecraft, java, fabric-loader) or origins we
            // could not turn into ordinary paths have no on-disk file to associate.
            boolean synthetic = origins.isEmpty();
            out.add(new InstalledMod(
                    meta.getId(),
                    meta.getName(),
                    meta.getVersion().getFriendlyString(),
                    "fabric",
                    origins,
                    nested,
                    synthetic));
        }
        return out;
    }

    /** Absolute, normalized paths of every JAR Fabric loaded as a mod origin. */
    public static Set<Path> loadedModPaths() {
        Set<Path> paths = new HashSet<>();
        for (InstalledMod mod : loadedMods()) {
            for (String p : mod.originPaths()) {
                paths.add(Path.of(p));
            }
        }
        return paths;
    }

    public static int loadedModCount() {
        return FabricLoader.getInstance().getAllMods().size();
    }

    /**
     * The instance's Minecraft version, read from the "minecraft" mod container's
     * metadata (no dependency on remapped MC classes). Null if unavailable.
     */
    public static String minecraftVersion() {
        return FabricLoader.getInstance().getModContainer("minecraft")
                .map(mc -> mc.getMetadata().getVersion().getFriendlyString())
                .orElse(null);
    }
}
