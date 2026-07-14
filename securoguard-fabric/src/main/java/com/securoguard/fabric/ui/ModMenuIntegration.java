package com.securoguard.fabric.ui;

import com.terraformersmc.modmenu.api.ConfigScreenFactory;
import com.terraformersmc.modmenu.api.ModMenuApi;

/**
 * Exposes the SecuroGuard status screen through Mod Menu's "configure" button.
 * Optional: if Mod Menu is absent this entry point is simply never invoked, and
 * the screen remains reachable via the {@code /securoguard} command surface.
 */
public final class ModMenuIntegration implements ModMenuApi {

    @Override
    public ConfigScreenFactory<?> getModConfigScreenFactory() {
        return SecuroGuardScreen::new;
    }
}
