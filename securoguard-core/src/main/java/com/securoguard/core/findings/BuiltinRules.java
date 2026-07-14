package com.securoguard.core.findings;

import com.securoguard.core.inventory.DiffResult;
import com.securoguard.core.inventory.FileRecord;
import com.securoguard.core.jar.JarInspectionResult;
import com.securoguard.core.reputation.ReputationResult;
import com.securoguard.core.reputation.ReputationStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * The MVP's built-in detection rules. Each rule is deliberately small and single
 * purpose so it can be reasoned about and tested in isolation, and the set can be
 * extended without touching the engine.
 *
 * <p>Guiding principle encoded here: <b>unknown is never malicious</b>. The
 * unknown-hash rule is INFO, and reputation absence never escalates severity.
 */
public final class BuiltinRules {

    private BuiltinRules() {
    }

    public static List<Rule> all() {
        List<Rule> rules = new ArrayList<>();
        rules.add(newJarInModsDuringSession());
        rules.add(newUntrustedJarPreLaunch());
        rules.add(knownMaliciousHash());
        rules.add(existingModChangedDuringSession());
        rules.add(misleadingDoubleExtension());
        rules.add(archiveTraversalEntries());
        rules.add(jarInOtherInstanceDirectory());
        rules.add(malformedOrOversizedArchive());
        rules.add(recognizedPlatformHash());
        rules.add(unknownHash());
        return rules;
    }

    // --- CRITICAL: a new JAR appeared in mods during an active session ---
    static Rule newJarInModsDuringSession() {
        return new SimpleRule("SG-NEW-JAR-IN-SESSION", ctx -> {
            // "New" is only meaningful relative to a trusted baseline.
            if (!ctx.sessionActive() || !ctx.baselineExists()) {
                return List.of();
            }
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : ctx.diff().added()) {
                if (r.inModsDir() && isJar(r)) {
                    String when = ctx.connectedToServer()
                            ? "while connected to a multiplayer server"
                            : "during an active game session";
                    out.add(Finding.builder("SG-NEW-JAR-IN-SESSION", Severity.CRITICAL)
                            .title("New mod JAR appeared in mods during a session")
                            .explanation("A JAR that was not in the approved baseline appeared in the "
                                    + "mods directory " + when + ". This matches the pattern of a mod being "
                                    + "dropped in for execution on a later launch. SecuroGuard does not claim "
                                    + "the server caused this, only that it occurred " + when + ".")
                            .evidence("path=" + r.relativePath() + " sha256=" + r.sha256() + " size=" + r.size())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.QUARANTINE)
                            .build());
                }
            }
            return out;
        });
    }

    // --- HIGH: a new, untrusted JAR appeared in mods since the baseline (pre-launch) ---
    // This is the Sentinel's headline case: a JAR written during a previous session
    // that would execute on the next launch. Only fires when no session is active so
    // it does not double-report with the CRITICAL in-session rule above.
    static Rule newUntrustedJarPreLaunch() {
        return new SimpleRule("SG-NEW-UNTRUSTED-JAR", ctx -> {
            // Only meaningful with a baseline to be "new" against; skip during sessions
            // (the CRITICAL in-session rule handles that case).
            if (ctx.sessionActive() || !ctx.baselineExists()) {
                return List.of();
            }
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : ctx.diff().added()) {
                if (r.inModsDir() && isJar(r)) {
                    out.add(Finding.builder("SG-NEW-UNTRUSTED-JAR", Severity.HIGH)
                            .title("New, untrusted mod JAR since the last approved baseline")
                            .explanation("A JAR in the mods directory is not part of the approved baseline. "
                                    + "If you did not install it yourself, it may have been dropped in by a "
                                    + "previous session and would execute on this launch. Review before playing.")
                            .evidence("path=" + r.relativePath() + " sha256=" + r.sha256() + " size=" + r.size())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.REVIEW)
                            .build());
                }
            }
            return out;
        });
    }

    // --- CRITICAL: a known-malicious hash ---
    static Rule knownMaliciousHash() {
        return new SimpleRule("SG-KNOWN-MALICIOUS-HASH", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : changedFiles(ctx.diff())) {
                if (ctx.isKnownMalicious(r.sha256())) {
                    out.add(Finding.builder("SG-KNOWN-MALICIOUS-HASH", Severity.CRITICAL)
                            .title("File matches a known-malicious hash")
                            .explanation("This file's SHA-256 is on the pinned known-malicious list.")
                            .evidence("path=" + r.relativePath() + " sha256=" + r.sha256())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.QUARANTINE)
                            .build());
                }
            }
            return out;
        });
    }

    // --- HIGH: an existing mod JAR changed during a session ---
    static Rule existingModChangedDuringSession() {
        return new SimpleRule("SG-MOD-JAR-CHANGED", ctx -> {
            if (!ctx.sessionActive()) {
                return List.of();
            }
            List<Finding> out = new ArrayList<>();
            List<DiffResult.Change> changes = new ArrayList<>();
            changes.addAll(ctx.diff().modified());
            changes.addAll(ctx.diff().replaced());
            for (DiffResult.Change c : changes) {
                FileRecord after = c.after();
                if (after.inModsDir() && isJar(after)) {
                    out.add(Finding.builder("SG-MOD-JAR-CHANGED", Severity.HIGH)
                            .title("An existing mod JAR changed during a session")
                            .explanation("A mod JAR present in the baseline was modified while the game was "
                                    + "running. Mods do not normally rewrite themselves mid-session.")
                            .evidence("path=" + after.relativePath()
                                    + " oldSha=" + c.before().sha256() + " newSha=" + after.sha256())
                            .affectedPath(after.relativePath())
                            .recommend(RecommendedAction.QUARANTINE)
                            .build());
                }
            }
            return out;
        });
    }

    // --- HIGH: misleading double extension ---
    static Rule misleadingDoubleExtension() {
        return new SimpleRule("SG-DOUBLE-EXTENSION", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : addedAndChanged(ctx.diff())) {
                JarInspectionResult ins = ctx.inspectionFor(r.relativePath());
                boolean flagged = (ins != null && ins.doubleExtension())
                        || com.securoguard.core.jar.JarInspector.hasDisguisedDoubleExtension(r.fileName());
                if (flagged) {
                    out.add(Finding.builder("SG-DOUBLE-EXTENSION", Severity.HIGH)
                            .title("JAR has a misleading double extension")
                            .explanation("The filename disguises an executable JAR as another file type "
                                    + "(e.g. a schematic or image). This is a common social-engineering trick.")
                            .evidence("filename=" + r.fileName())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.QUARANTINE)
                            .build());
                }
            }
            return out;
        });
    }

    // --- HIGH: archive contains traversal entry names ---
    static Rule archiveTraversalEntries() {
        return new SimpleRule("SG-ARCHIVE-TRAVERSAL", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : addedAndChanged(ctx.diff())) {
                JarInspectionResult ins = ctx.inspectionFor(r.relativePath());
                if (ins != null && !ins.traversalEntryNames().isEmpty()) {
                    out.add(Finding.builder("SG-ARCHIVE-TRAVERSAL", Severity.HIGH)
                            .title("Archive contains path-traversal entries")
                            .explanation("The archive has entries whose names escape the extraction directory "
                                    + "(e.g. '../'). Legitimate mods never need this; it targets naive extractors.")
                            .evidence("entries=" + ins.traversalEntryNames())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.QUARANTINE)
                            .build());
                }
            }
            return out;
        });
    }

    // --- MEDIUM: a JAR appeared in another configured instance directory ---
    static Rule jarInOtherInstanceDirectory() {
        return new SimpleRule("SG-JAR-OTHER-DIR", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : ctx.diff().added()) {
                if (!r.inModsDir() && isJar(r)) {
                    out.add(Finding.builder("SG-JAR-OTHER-DIR", Severity.MEDIUM)
                            .title("A JAR appeared outside the mods directory")
                            .explanation("A new JAR was found in the instance but not in the mods folder. "
                                    + "This may be benign (e.g. a library cache) but is worth reviewing.")
                            .evidence("path=" + r.relativePath() + " sha256=" + r.sha256())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.REVIEW)
                            .build());
                }
            }
            return out;
        });
    }

    // --- MEDIUM: malformed or oversized archive ---
    static Rule malformedOrOversizedArchive() {
        return new SimpleRule("SG-MALFORMED-ARCHIVE", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : addedAndChanged(ctx.diff())) {
                JarInspectionResult ins = ctx.inspectionFor(r.relativePath());
                if (ins != null && (!ins.problems().isEmpty() || ins.limitExceeded())) {
                    out.add(Finding.builder("SG-MALFORMED-ARCHIVE", Severity.MEDIUM)
                            .title("Archive is malformed or exceeds safe inspection limits")
                            .explanation("SecuroGuard could not fully and safely inspect this archive. That "
                                    + "does not prove malice, but an archive that resists inspection warrants review.")
                            .evidence("problems=" + ins.problems() + " limitExceeded=" + ins.limitExceeded())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.REVIEW)
                            .build());
                }
            }
            return out;
        });
    }

    // --- INFO: recognized platform (Modrinth) hash ---
    static Rule recognizedPlatformHash() {
        return new SimpleRule("SG-PLATFORM-KNOWN-HASH", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : ctx.diff().added()) {
                ReputationResult rep = ctx.reputationFor(r.sha256());
                if (rep != null && rep.status() == ReputationStatus.KNOWN_ON_PLATFORM) {
                    out.add(Finding.builder("SG-PLATFORM-KNOWN-HASH", Severity.INFO)
                            .title("File recognised on a hosting platform")
                            .explanation("This file's hash matches a published project version. This is "
                                    + "reassuring context, not a guarantee of safety.")
                            .evidence("project=" + rep.projectName() + " version=" + rep.versionName())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.NONE)
                            .build());
                }
            }
            return out;
        });
    }

    // --- INFO: unknown hash (NEVER malicious) ---
    static Rule unknownHash() {
        return new SimpleRule("SG-UNKNOWN-HASH", ctx -> {
            List<Finding> out = new ArrayList<>();
            for (FileRecord r : ctx.diff().added()) {
                if (!isJar(r)) {
                    continue;
                }
                ReputationResult rep = ctx.reputationFor(r.sha256());
                boolean unknown = rep == null || rep.status() == ReputationStatus.UNKNOWN;
                if (unknown) {
                    out.add(Finding.builder("SG-UNKNOWN-HASH", Severity.INFO)
                            .title("Unknown file hash")
                            .explanation("This file's hash is not recognised. Unknown does NOT mean malicious: "
                                    + "private packs, dev builds and new mods are all legitimately unknown.")
                            .evidence("path=" + r.relativePath() + " sha256=" + r.sha256())
                            .affectedPath(r.relativePath())
                            .recommend(RecommendedAction.MONITOR)
                            .build());
                }
            }
            return out;
        });
    }

    // --- helpers ---

    private static boolean isJar(FileRecord r) {
        return r.fileName().toLowerCase(Locale.ROOT).endsWith(".jar");
    }

    private static List<FileRecord> changedFiles(DiffResult diff) {
        List<FileRecord> out = new ArrayList<>(diff.added());
        for (DiffResult.Change c : diff.modified()) {
            out.add(c.after());
        }
        for (DiffResult.Change c : diff.replaced()) {
            out.add(c.after());
        }
        for (DiffResult.Rename r : diff.renamed()) {
            out.add(r.to());
        }
        return out;
    }

    private static List<FileRecord> addedAndChanged(DiffResult diff) {
        return changedFiles(diff);
    }

    /** Minimal {@link Rule} whose behaviour is a function; keeps rule classes tiny. */
    private record SimpleRule(String id, Function<RuleContext, List<Finding>> fn) implements Rule {
        @Override
        public List<Finding> evaluate(RuleContext context) {
            return fn.apply(context);
        }
    }
}
