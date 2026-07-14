package com.securoguard.sentinel;

/**
 * Documented process exit codes. These are a stable contract so a launcher's
 * pre-launch hook can branch on the result (e.g. block launch on CRITICAL).
 */
public final class ExitCode {

    /** Scan completed; nothing that should block a launch. */
    public static final int OK = 0;
    /** Warnings present (MEDIUM/HIGH findings) but not critical. */
    public static final int WARNINGS = 1;
    /** At least one CRITICAL finding; a launcher should consider blocking. */
    public static final int CRITICAL = 2;
    /** Bad arguments / configuration (e.g. missing --game-dir). */
    public static final int CONFIG_ERROR = 3;
    /** An unexpected internal failure. */
    public static final int INTERNAL_ERROR = 4;

    private ExitCode() {
    }
}
