package com.securoguard.fabric.ui;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RecommendedAction;
import com.securoguard.core.findings.Severity;
import com.securoguard.fabric.SecuroGuardClient;
import com.securoguard.fabric.SecuroGuardRuntime;

import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.ConfirmScreen;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.Text;
import net.minecraft.util.Formatting;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Full detail for one finding, with explicit, confirmed actions. Shows severity,
 * rule/advisory id, path, SHA-256, explanation and recommended action. Quarantine
 * is only offered when enabled in config, always routes through a confirmation, and
 * is disabled while an operation is pending so a double-click cannot double-run it.
 */
public final class FindingDetailScreen extends Screen {

    private static final Pattern SHA256 = Pattern.compile("sha256=([0-9a-f]{64})");

    private final Screen parent;
    private final Finding finding;
    private ButtonWidget quarantineButton;
    private volatile boolean pending;
    private Text status = Text.empty();

    public FindingDetailScreen(Screen parent, Finding finding) {
        super(Text.translatable("securoguard.detail.title"));
        this.parent = parent;
        this.finding = finding;
    }

    @Override
    protected void init() {
        SecuroGuardRuntime rt = SecuroGuardClient.runtime();
        int cx = this.width / 2;
        int y = this.height - 56;

        boolean quarantineOffered = rt != null && rt.quarantineEnabled() && finding.affectedPath() != null
                && (finding.recommendedAction() == RecommendedAction.QUARANTINE
                    || finding.severity() == Severity.CRITICAL || finding.severity() == Severity.HIGH);
        if (quarantineOffered) {
            quarantineButton = ButtonWidget.builder(Text.translatable("securoguard.button.quarantine"),
                    b -> confirmQuarantine(rt)).dimensions(cx - 154, y, 100, 20).build();
            addDrawableChild(quarantineButton);
        }

        addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.dismiss"), b -> {
            if (rt != null) {
                rt.findings().dismiss(finding); // hides the warning WITHOUT granting trust
            }
            this.close();
        }).dimensions(cx - 50, y, 100, 20).build());

        // Offer disconnect only for serious findings while genuinely on a server.
        boolean serious = finding.severity() == Severity.CRITICAL || finding.severity() == Severity.HIGH;
        if (rt != null && serious && rt.session().isConnectedToServer()) {
            addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.disconnect"),
                    b -> rt.disconnectFromServer()).dimensions(cx + 54, y, 100, 20).build());
        }

        addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.back"), b -> this.close())
                .dimensions(cx - 100, this.height - 30, 200, 20).build());
    }

    private void confirmQuarantine(SecuroGuardRuntime rt) {
        ConfirmScreen confirm = new ConfirmScreen(
                accepted -> {
                    if (accepted && rt != null && !pending) {
                        pending = true;
                        if (quarantineButton != null) {
                            quarantineButton.active = false; // prevent a second click while running
                        }
                        status = Text.translatable("securoguard.status.quarantining").formatted(Formatting.YELLOW);
                        rt.quarantineAsync(finding, (ok, message) -> {
                            pending = false;
                            status = Text.literal(message).formatted(ok ? Formatting.GREEN : Formatting.RED);
                            if (ok) {
                                // The file is gone; go back to the (refreshed) list.
                                this.client.setScreen(new FindingsScreen(parent));
                            } else if (quarantineButton != null) {
                                quarantineButton.active = true; // allow retry on failure
                            }
                        });
                    } else {
                        this.client.setScreen(this);
                    }
                },
                Text.translatable("securoguard.button.confirm_quarantine"),
                Text.translatable("securoguard.confirm.quarantine.msg", String.valueOf(finding.affectedPath())));
        this.client.setScreen(confirm);
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        super.render(context, mouseX, mouseY, delta);
        int x = Math.max(8, this.width / 2 - 200);
        int y = 24;
        int line = 12;

        context.drawTextWithShadow(this.textRenderer, Text.literal("[" + finding.severity() + "] "
                + finding.ruleId()).formatted(colour(finding.severity())), x, y, 0xFFFFFF);
        y += line + 2;
        y = field(context, x, y, "securoguard.detail.path", String.valueOf(finding.affectedPath()));
        y = field(context, x, y, "securoguard.detail.sha256", sha256(finding));
        y = field(context, x, y, "securoguard.detail.action", finding.recommendedAction().name());
        y += 4;
        // Explanation wrapped across the width.
        for (var wrapped : this.textRenderer.wrapLines(Text.literal(finding.explanation()), this.width - 2 * x)) {
            context.drawTextWithShadow(this.textRenderer, wrapped, x, y, 0xCCCCCC);
            y += line;
        }
        if (!status.getString().isEmpty()) {
            context.drawTextWithShadow(this.textRenderer, status, x, this.height - 44, 0xFFFFFF);
        }
    }

    private int field(DrawContext context, int x, int y, String labelKey, String value) {
        Text label = Text.translatable(labelKey).formatted(Formatting.GRAY);
        context.drawTextWithShadow(this.textRenderer, label, x, y, 0xAAAAAA);
        context.drawTextWithShadow(this.textRenderer, Text.literal(trim(value, 60)),
                x + this.textRenderer.getWidth(label) + 6, y, 0xFFFFFF);
        return y + 12;
    }

    private static Formatting colour(Severity s) {
        return switch (s) {
            case CRITICAL, HIGH -> Formatting.RED;
            case MEDIUM -> Formatting.GOLD;
            default -> Formatting.GRAY;
        };
    }

    private static String sha256(Finding f) {
        Matcher m = SHA256.matcher(f.evidence() == null ? "" : f.evidence());
        return m.find() ? m.group(1) : "(n/a)";
    }

    private static String trim(String s, int max) {
        if (s == null) {
            return "";
        }
        return s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    @Override
    public void close() {
        this.client.setScreen(parent);
    }
}
