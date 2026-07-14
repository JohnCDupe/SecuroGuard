package com.securoguard.core.findings;

import com.securoguard.core.inventory.DiffResult;
import com.securoguard.core.inventory.FileRecord;
import com.securoguard.core.inventory.FileType;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class RuleEngineTest {

    private FileRecord jar(String rel, String hash) {
        String name = rel.substring(rel.lastIndexOf('/') + 1);
        return new FileRecord("/abs/" + rel, rel, name, 100, 0L, hash,
                FileType.ZIP_ARCHIVE, rel.startsWith("mods/"), false);
    }

    private DiffResult added(FileRecord... records) {
        return new DiffResult(List.of(records), List.of(), List.of(), List.of(), List.of());
    }

    @Test
    void newJarInModsDuringSessionIsCritical() {
        RuleEngine engine = RuleEngine.withDefaultRules();
        RuleContext ctx = RuleContext.builder(added(jar("mods/new.jar", "abc")))
                .sessionActive(true).connectedToServer(true).build();

        List<Finding> findings = engine.evaluate(ctx);
        assertTrue(findings.stream().anyMatch(f ->
                f.ruleId().equals("SG-NEW-JAR-IN-SESSION") && f.severity() == Severity.CRITICAL));
        // Findings are sorted most-severe first.
        assertEquals(Severity.CRITICAL, findings.get(0).severity());
    }

    @Test
    void newJarWithoutActiveSessionIsNotCritical() {
        RuleEngine engine = RuleEngine.withDefaultRules();
        RuleContext ctx = RuleContext.builder(added(jar("mods/new.jar", "abc")))
                .sessionActive(false).build();
        assertTrue(engine.evaluate(ctx).stream().noneMatch(f -> f.severity() == Severity.CRITICAL));
    }

    @Test
    void knownMaliciousHashIsCritical() {
        RuleEngine engine = RuleEngine.withDefaultRules();
        RuleContext ctx = RuleContext.builder(added(jar("mods/x.jar", "badhash")))
                .knownMaliciousHashes(Set.of("badhash")).build();
        assertTrue(engine.evaluate(ctx).stream().anyMatch(f ->
                f.ruleId().equals("SG-KNOWN-MALICIOUS-HASH") && f.severity() == Severity.CRITICAL));
    }

    @Test
    void unknownHashIsInformationalNeverMalicious() {
        RuleEngine engine = RuleEngine.withDefaultRules();
        RuleContext ctx = RuleContext.builder(added(jar("mods/mystery.jar", "unknownhash"))).build();
        List<Finding> findings = engine.evaluate(ctx);
        assertTrue(findings.stream().anyMatch(f -> f.ruleId().equals("SG-UNKNOWN-HASH")));
        // The unknown-hash finding must be INFO, not an escalation.
        Finding unknown = findings.stream().filter(f -> f.ruleId().equals("SG-UNKNOWN-HASH"))
                .findFirst().orElseThrow();
        assertEquals(Severity.INFO, unknown.severity());
    }
}
