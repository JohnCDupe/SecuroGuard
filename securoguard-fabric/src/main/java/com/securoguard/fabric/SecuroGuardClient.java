package com.securoguard.fabric;

import com.securoguard.core.instance.InstancePaths;
import com.securoguard.core.service.SecuroGuardConfig;
import com.securoguard.fabric.command.SecuroGuardCommands;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientLifecycleEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.loader.api.FabricLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;

/**
 * Client entry point. Wires SecuroGuard to Fabric Loader (authoritative game and
 * mods directories, loaded-mod inventory), tracks session/connection state, starts
 * the async initial scan + monitor, and registers client commands.
 *
 * <p>Honest scope note: this mod and any hostile mod run in the same JVM with the
 * same privileges. SecuroGuard provides Minecraft-aware detection and evidence, it
 * does not sandbox code that is already executing. See the threat model.
 */
public final class SecuroGuardClient implements ClientModInitializer {

    private static final Logger LOG = LoggerFactory.getLogger("SecuroGuard");

    private static volatile SecuroGuardRuntime runtime;

    /** Global accessor for the running runtime (screens, commands, Mod Menu). */
    public static SecuroGuardRuntime runtime() {
        return runtime;
    }

    @Override
    public void onInitializeClient() {
        // Obtain the true game/mods directories from Fabric Loader — never assume .minecraft.
        Path gameDir = FabricLoader.getInstance().getGameDir();
        InstancePaths paths = InstancePaths.ofGameDir(gameDir);
        try {
            paths.createDataDirectories();
        } catch (Exception e) {
            LOG.error("SecuroGuard could not create its data directory; continuing best-effort", e);
        }

        SecuroGuardConfig config = SecuroGuardConfig.loadOrDefault(
                paths.configDir().resolve("securoguard.json"));

        SecuroGuardRuntime rt = new SecuroGuardRuntime(paths, config);
        runtime = rt;

        // Session/connection tracking. Single-player uses the integrated server and
        // is tracked separately from multiplayer. No server address is stored.
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) ->
                rt.session().onJoin(client.isIntegratedServerRunning()));
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) ->
                rt.session().onDisconnect());

        SecuroGuardCommands.register();

        ClientLifecycleEvents.CLIENT_STOPPING.register(client -> rt.close());

        // Initial comparison + monitor start happen asynchronously off the main thread.
        rt.startAsync();
        LOG.info("SecuroGuard initialised for {}", gameDir);
    }
}
