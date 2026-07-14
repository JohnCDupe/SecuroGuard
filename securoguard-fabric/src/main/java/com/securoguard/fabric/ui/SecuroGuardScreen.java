package com.securoguard.fabric.ui;

import com.securoguard.core.findings.Severity;
import com.securoguard.fabric.SecuroGuardClient;
import com.securoguard.fabric.SecuroGuardRuntime;
import com.securoguard.fabric.SessionState;

import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.Text;

/**
 * Minimal, version-robust status screen. It deliberately avoids elaborate custom
 * widgets (which are the most version-sensitive part of a Fabric UI) in favour of
 * stable primitives: text lines plus vanilla buttons. See docs for the richer UI
 * envisioned as a follow-up.
 */
public final class SecuroGuardScreen extends Screen {

    private final Screen parent;

    public SecuroGuardScreen(Screen parent) {
        super(Text.translatable("securoguard.screen.title"));
        this.parent = parent;
    }

    @Override
    protected void init() {
        int cx = this.width / 2;
        int y = this.height - 52;

        addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.rescan"), b -> {
            SecuroGuardRuntime rt = SecuroGuardClient.runtime();
            if (rt != null) {
                rt.requestRescan();
            }
        }).dimensions(cx - 154, y, 100, 20).build());

        addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.open_findings"),
                b -> this.client.setScreen(new FindingsScreen(this)))
                .dimensions(cx - 50, y, 100, 20).build());

        addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.done"), b -> this.close())
                .dimensions(cx + 54, y, 100, 20).build());
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        super.render(context, mouseX, mouseY, delta);
        SecuroGuardRuntime rt = SecuroGuardClient.runtime();

        int cx = this.width / 2;
        context.drawCenteredTextWithShadow(this.textRenderer, this.title, cx, 24, 0xFFFFFF);

        int y = 60;
        int line = 14;
        String monitoring = rt != null ? rt.monitorHealth() : "not started";
        String baseline = rt != null && rt.baselinePresent() ? "present" : "not established";

        int findingsCount = rt != null ? rt.findings().active().size() : 0;
        Severity highest = rt != null ? rt.findings().highestActiveSeverity() : null;

        drawLine(context, cx, y, "Monitoring: " + monitoring); y += line;
        drawLine(context, cx, y, "Baseline: " + baseline); y += line;
        drawLine(context, cx, y, "Findings: " + findingsCount
                + (highest != null ? " (highest: " + highest + ")" : "")); y += line;
        drawLine(context, cx, y, "Session: " + sessionLabel(rt)); y += line + 6;

        if (rt != null && rt.findings().hasActiveCritical()) {
            context.drawCenteredTextWithShadow(this.textRenderer,
                    Text.literal("CRITICAL: a new JAR appeared in mods during this session."),
                    cx, y, 0xFF5555);
        } else {
            context.drawCenteredTextWithShadow(this.textRenderer,
                    Text.translatable("securoguard.warn.unknown_not_malicious"), cx, y, 0xAAAAAA);
        }
    }

    private void drawLine(DrawContext context, int cx, int y, String text) {
        context.drawCenteredTextWithShadow(this.textRenderer, Text.literal(text), cx, y, 0xE0E0E0);
    }

    private String sessionLabel(SecuroGuardRuntime rt) {
        if (rt == null) {
            return "unknown";
        }
        SessionState.Kind kind = rt.session().kind();
        return switch (kind) {
            case MULTIPLAYER -> "connected to a server";
            case SINGLEPLAYER -> "single-player";
            case DISCONNECTED -> "in menus";
        };
    }

    @Override
    public void close() {
        this.client.setScreen(parent);
    }
}
