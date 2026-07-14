package com.securoguard.core.findings;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Runs a set of {@link Rule}s over a {@link RuleContext} and returns the combined
 * findings, most-severe first. The engine owns ordering and error isolation so a
 * single misbehaving rule cannot suppress the others' findings.
 */
public final class RuleEngine {

    private final List<Rule> rules;

    public RuleEngine(List<Rule> rules) {
        this.rules = List.copyOf(rules);
    }

    /** The default rule set covering the MVP's documented detections. */
    public static RuleEngine withDefaultRules() {
        return new RuleEngine(BuiltinRules.all());
    }

    public List<Finding> evaluate(RuleContext context) {
        List<Finding> all = new ArrayList<>();
        for (Rule rule : rules) {
            try {
                all.addAll(rule.evaluate(context));
            } catch (RuntimeException e) {
                // A broken rule becomes a low-severity finding rather than taking
                // down the whole evaluation. We do not swallow it silently.
                all.add(Finding.builder("SG-RULE-ERROR", Severity.LOW)
                        .title("Rule '" + rule.id() + "' failed to evaluate")
                        .explanation("An internal rule error occurred; other checks still ran.")
                        .evidence(String.valueOf(e))
                        .recommend(RecommendedAction.REVIEW)
                        .build());
            }
        }
        all.sort(Comparator.comparing(Finding::severity).reversed());
        return all;
    }

    public List<Rule> rules() {
        return rules;
    }
}
