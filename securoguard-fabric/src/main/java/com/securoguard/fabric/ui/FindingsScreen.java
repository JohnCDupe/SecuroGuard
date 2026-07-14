package com.securoguard.fabric.ui;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.Severity;
import com.securoguard.fabric.SecuroGuardClient;
import com.securoguard.fabric.SecuroGuardRuntime;

import net.minecraft.client.gui.DrawContext;
import net.minecraft.client.gui.screen.Screen;
import net.minecraft.client.gui.widget.ButtonWidget;
import net.minecraft.text.Text;

import java.util.List;

/**
 * Paginated list of active findings. Rows open a {@link FindingDetailScreen} for
 * the full record and actions. Pagination (rather than a fixed six-row cap) means
 * an arbitrary number of findings is reachable. A "Disconnect From Server" shortcut
 * is offered when there is a serious finding and the client is on a server.
 */
public final class FindingsScreen extends Screen {

    private static final int PER_PAGE = 5;

    private final Screen parent;
    private int page;

    public FindingsScreen(Screen parent) {
        super(Text.translatable("securoguard.findings.title"));
        this.parent = parent;
    }

    @Override
    protected void init() {
        SecuroGuardRuntime rt = SecuroGuardClient.runtime();
        List<Finding> findings = rt != null ? rt.findings().active() : List.of();
        int pages = Math.max(1, (findings.size() + PER_PAGE - 1) / PER_PAGE);
        page = Math.max(0, Math.min(page, pages - 1));

        int cx = this.width / 2;
        int y = 40;
        int start = page * PER_PAGE;
        for (int i = start; i < Math.min(start + PER_PAGE, findings.size()); i++) {
            Finding f = findings.get(i);
            String label = "[" + f.severity() + "] " + trim(f.title(), 34);
            addDrawableChild(ButtonWidget.builder(Text.literal(label),
                            b -> this.client.setScreen(new FindingDetailScreen(this, f)))
                    .dimensions(cx - 200, y, 400, 20).build());
            y += 24;
        }

        int navY = this.height - 52;
        ButtonWidget prev = ButtonWidget.builder(Text.translatable("securoguard.button.prev"),
                b -> { page--; this.clearAndInit(); }).dimensions(cx - 154, navY, 100, 20).build();
        prev.active = page > 0;
        addDrawableChild(prev);
        ButtonWidget next = ButtonWidget.builder(Text.translatable("securoguard.button.next"),
                b -> { page++; this.clearAndInit(); }).dimensions(cx + 54, navY, 100, 20).build();
        next.active = page < pages - 1;
        addDrawableChild(next);

        // Disconnect shortcut for serious findings while genuinely on a server.
        boolean serious = findings.stream().anyMatch(f ->
                f.severity() == Severity.CRITICAL || f.severity() == Severity.HIGH);
        if (rt != null && serious && rt.session().isConnectedToServer()) {
            addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.disconnect"),
                    b -> rt.disconnectFromServer()).dimensions(cx - 50, navY, 100, 20).build());
        }

        addDrawableChild(ButtonWidget.builder(Text.translatable("securoguard.button.done"), b -> this.close())
                .dimensions(cx - 100, this.height - 28, 200, 20).build());
    }

    @Override
    public void render(DrawContext context, int mouseX, int mouseY, float delta) {
        super.render(context, mouseX, mouseY, delta);
        int cx = this.width / 2;
        context.drawCenteredTextWithShadow(this.textRenderer, this.title, cx, 16, 0xFFFFFF);

        SecuroGuardRuntime rt = SecuroGuardClient.runtime();
        List<Finding> findings = rt != null ? rt.findings().active() : List.of();
        if (findings.isEmpty()) {
            context.drawCenteredTextWithShadow(this.textRenderer,
                    Text.translatable("securoguard.findings.empty"), cx, this.height / 2, 0xAAAAAA);
            return;
        }
        int pages = Math.max(1, (findings.size() + PER_PAGE - 1) / PER_PAGE);
        context.drawCenteredTextWithShadow(this.textRenderer,
                Text.translatable("securoguard.findings.page", (page + 1), pages, findings.size()),
                cx, 28, 0xBBBBBB);
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
