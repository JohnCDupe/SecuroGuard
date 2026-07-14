package com.securoguard.sentinel;

import java.util.HashMap;
import java.util.Map;

/**
 * Tiny flag parser for {@code --key value} and boolean {@code --flag} options.
 * Deliberately minimal — no external CLI framework — since the Sentinel has a
 * small, fixed set of options.
 */
final class Args {

    private final String command;
    private final Map<String, String> options = new HashMap<>();

    private Args(String command) {
        this.command = command;
    }

    static Args parse(String[] argv) {
        String command = argv.length > 0 ? argv[0] : "";
        Args args = new Args(command);
        for (int i = 1; i < argv.length; i++) {
            String a = argv[i];
            if (a.startsWith("--")) {
                String key = a.substring(2);
                if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) {
                    args.options.put(key, argv[++i]);
                } else {
                    args.options.put(key, "true"); // boolean flag
                }
            }
        }
        return args;
    }

    String command() {
        return command;
    }

    String get(String key) {
        return options.get(key);
    }

    boolean has(String key) {
        return options.containsKey(key);
    }
}
