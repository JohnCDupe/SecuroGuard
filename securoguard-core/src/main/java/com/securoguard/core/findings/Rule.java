package com.securoguard.core.findings;

import java.util.List;

/**
 * A single, composable detection rule. Rules are pure functions from a
 * {@link RuleContext} to zero or more {@link Finding}s. Keeping them free of I/O
 * and UI concerns makes them individually testable and freely combinable in a
 * {@link RuleEngine}.
 */
public interface Rule {

    /** Stable identifier, e.g. {@code "SG-NEW-JAR-IN-SESSION"}. */
    String id();

    List<Finding> evaluate(RuleContext context);
}
