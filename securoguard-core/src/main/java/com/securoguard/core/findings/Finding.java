package com.securoguard.core.findings;

import java.time.Instant;

/**
 * A structured, self-explanatory finding. Findings are data, not UI: they carry
 * enough context (evidence, affected path, recommendation) for any front end to
 * render and act on them consistently.
 *
 * @param ruleId            stable identifier of the rule that produced this
 * @param severity          {@link Severity}
 * @param title             short human-readable headline
 * @param explanation       plain-language description of what and why
 * @param evidence          the concrete facts (hash, entry name, sizes, …)
 * @param affectedPath      instance-relative path, or {@code null} if not file-scoped
 * @param recommendedAction machine-readable next step
 * @param timestamp         when the finding was produced
 */
public record Finding(
        String ruleId,
        Severity severity,
        String title,
        String explanation,
        String evidence,
        String affectedPath,
        RecommendedAction recommendedAction,
        Instant timestamp) {

    public static Builder builder(String ruleId, Severity severity) {
        return new Builder(ruleId, severity);
    }

    public static final class Builder {
        private final String ruleId;
        private final Severity severity;
        private String title = "";
        private String explanation = "";
        private String evidence = "";
        private String affectedPath;
        private RecommendedAction recommendedAction = RecommendedAction.REVIEW;
        private Instant timestamp = Instant.now();

        private Builder(String ruleId, Severity severity) {
            this.ruleId = ruleId;
            this.severity = severity;
        }

        public Builder title(String v) {
            this.title = v;
            return this;
        }

        public Builder explanation(String v) {
            this.explanation = v;
            return this;
        }

        public Builder evidence(String v) {
            this.evidence = v;
            return this;
        }

        public Builder affectedPath(String v) {
            this.affectedPath = v;
            return this;
        }

        public Builder recommend(RecommendedAction v) {
            this.recommendedAction = v;
            return this;
        }

        public Builder timestamp(Instant v) {
            this.timestamp = v;
            return this;
        }

        public Finding build() {
            return new Finding(ruleId, severity, title, explanation, evidence,
                    affectedPath, recommendedAction, timestamp);
        }
    }
}
