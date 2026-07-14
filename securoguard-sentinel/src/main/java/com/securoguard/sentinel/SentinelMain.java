package com.securoguard.sentinel;

/**
 * Process entry point. Delegates to {@link Sentinel#run} and maps the result to a
 * process exit code so launchers can gate on it. All real logic lives in
 * {@link Sentinel} to keep it testable without spawning a JVM.
 */
public final class SentinelMain {

    public static void main(String[] args) {
        int code = new Sentinel(System.out, System.err).run(args);
        System.exit(code);
    }

    private SentinelMain() {
    }
}
