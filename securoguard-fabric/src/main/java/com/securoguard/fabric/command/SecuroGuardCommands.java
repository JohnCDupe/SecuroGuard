package com.securoguard.fabric.command;

import com.securoguard.core.findings.Finding;
import com.securoguard.fabric.SecuroGuardRuntime;
import com.securoguard.fabric.SecuroGuardClient;

import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import java.util.List;

import static net.fabricmc.fabric.api.client.command.v2.ClientCommandManager.literal;

/**
 * Registers the client-side {@code /securoguard} commands. These are purely local
 * client commands (they never reach the server) and provide a keyboard path to the
 * same information as the screen.
 */
public final class SecuroGuardCommands {

    private SecuroGuardCommands() {
    }

    public static void register() {
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, registryAccess) ->
                dispatcher.register(literal("securoguard")
                        .then(literal("status").executes(ctx -> status(ctx.getSource())))
                        .then(literal("scan").executes(ctx -> scan(ctx.getSource())))
                        .then(literal("findings").executes(ctx -> findings(ctx.getSource())))));
    }

    private static int status(FabricClientCommandSource source) {
        SecuroGuardRuntime rt = SecuroGuardClient.runtime();
        if (rt == null) {
            source.sendFeedback(Text.literal("SecuroGuard is not initialised."));
            return 0;
        }
        String monitoring = rt.isMonitoring() ? "active" : "inactive";
        String baseline = rt.baselinePresent() ? "present" : "not established";
        int count = rt.findings().active().size();
        source.sendFeedback(Text.literal("SecuroGuard — monitoring: " + monitoring
                + ", baseline: " + baseline + ", findings: " + count));
        return 1;
    }

    private static int scan(FabricClientCommandSource source) {
        SecuroGuardRuntime rt = SecuroGuardClient.runtime();
        if (rt == null) {
            source.sendFeedback(Text.literal("SecuroGuard is not initialised."));
            return 0;
        }
        rt.requestRescan();
        source.sendFeedback(Text.literal("SecuroGuard: re-scan started…"));
        return 1;
    }

    private static int findings(FabricClientCommandSource source) {
        SecuroGuardRuntime rt = SecuroGuardClient.runtime();
        if (rt == null) {
            source.sendFeedback(Text.literal("SecuroGuard is not initialised."));
            return 0;
        }
        List<Finding> active = rt.findings().active();
        if (active.isEmpty()) {
            source.sendFeedback(Text.literal("SecuroGuard: no findings. (Unknown files are not threats.)"));
            return 1;
        }
        source.sendFeedback(Text.literal("SecuroGuard findings (" + active.size() + "):")
                .formatted(Formatting.YELLOW));
        for (Finding f : active) {
            Formatting colour = switch (f.severity()) {
                case CRITICAL, HIGH -> Formatting.RED;
                case MEDIUM -> Formatting.GOLD;
                default -> Formatting.GRAY;
            };
            source.sendFeedback(Text.literal("  [" + f.severity() + "] " + f.title()
                    + (f.affectedPath() != null ? " — " + f.affectedPath() : "")).formatted(colour));
        }
        return 1;
    }
}
