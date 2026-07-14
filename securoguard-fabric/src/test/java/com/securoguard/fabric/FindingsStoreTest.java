package com.securoguard.fabric;

import com.securoguard.core.findings.Finding;
import com.securoguard.core.findings.RecommendedAction;
import com.securoguard.core.findings.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Deterministic, headless coverage of the Fabric-side findings logic (no Minecraft
 * classes touched), per R10 — the pieces the graphical smoke test cannot assert.
 */
class FindingsStoreTest {

    private Finding finding(String ruleId, Severity sev, String path, String evidence) {
        return Finding.builder(ruleId, sev).title("t").affectedPath(path).evidence(evidence)
                .recommend(RecommendedAction.QUARANTINE).build();
    }

    @Test
    void dismissHidesFromActiveButDoesNotGrantTrust() {
        FindingsStore store = new FindingsStore();
        Finding f = finding("SG-NEW-JAR-IN-SESSION", Severity.CRITICAL, "mods/x.jar", "sha256=aa");
        store.replaceAll(List.of(f));
        assertEquals(1, store.active().size());

        store.dismiss(f);
        assertTrue(store.active().isEmpty(), "dismissed finding is hidden");
        // 'all' still contains it — dismissing hides, it does not delete or trust.
        assertEquals(1, store.all().size());
    }

    @Test
    void changedHashProducesADistinctFindingThatIsNotSuppressedByAnOldDismissal() {
        FindingsStore store = new FindingsStore();
        Finding original = finding("SG-NEW-JAR-IN-SESSION", Severity.CRITICAL, "mods/x.jar", "sha256=aa");
        store.replaceAll(List.of(original));
        store.dismiss(original);
        assertTrue(store.active().isEmpty());

        // Same path, new content (new hash in the evidence) -> different key -> re-alerts.
        Finding changed = finding("SG-NEW-JAR-IN-SESSION", Severity.CRITICAL, "mods/x.jar", "sha256=bb");
        store.replaceAll(List.of(changed));
        assertEquals(1, store.active().size(), "a changed hash must not be suppressed by an old dismissal");
        assertNotEquals(FindingsStore.keyOf(original), FindingsStore.keyOf(changed));
    }

    @Test
    void highestActiveSeverityAndCriticalFlag() {
        FindingsStore store = new FindingsStore();
        store.replaceAll(List.of(
                finding("SG-UNKNOWN-HASH", Severity.INFO, "mods/a.jar", "sha256=1"),
                finding("SG-NEW-JAR-IN-SESSION", Severity.CRITICAL, "mods/b.jar", "sha256=2")));
        assertEquals(Severity.CRITICAL, store.highestActiveSeverity());
        assertTrue(store.hasActiveCritical());

        store.dismiss(store.active().stream().filter(f -> f.severity() == Severity.CRITICAL).findFirst().get());
        assertFalse(store.hasActiveCritical(), "dismissing the critical clears the critical flag");
        assertEquals(Severity.INFO, store.highestActiveSeverity());
    }
}
