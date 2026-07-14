package com.securoguard.core.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

/**
 * Shared Gson instance. Gson is used deliberately instead of Java native
 * serialization: SecuroGuard must never {@code readObject} untrusted bytes, and
 * a documented text format is auditable. Pretty printing keeps on-disk state
 * human-reviewable.
 */
public final class Json {

    private static final Gson GSON = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .create();

    private Json() {
    }

    public static Gson gson() {
        return GSON;
    }
}
