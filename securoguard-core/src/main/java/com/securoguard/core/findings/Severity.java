package com.securoguard.core.findings;

/**
 * Finding severity, ordered from least to most serious. Ordinal order is
 * meaningful: {@code CRITICAL.compareTo(INFO) > 0}.
 *
 * <p>Note that {@code INFO} explicitly covers "unknown" outcomes. An unknown hash
 * is informational, never an accusation — see the README's prominent warning.
 */
public enum Severity {
    INFO,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
}
