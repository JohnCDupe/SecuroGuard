package com.securoguard.core.jar;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Bounded, descriptive result of inspecting an archive. Everything here is
 * observation, not judgement — the rule engine decides what (if anything) is
 * suspicious. Malformed archives populate {@link #problems()} rather than throwing.
 */
public final class JarInspectionResult {

    private boolean structurallyValidZip;
    private ModMetadata modMetadata;              // nullable
    private final List<String> manifestAttributes = new ArrayList<>();
    private final List<String> nestedJarEntries = new ArrayList<>();
    private boolean hasSignatureEntries;
    private boolean doubleExtension;
    private final List<String> traversalEntryNames = new ArrayList<>();
    private final List<String> problems = new ArrayList<>();
    private boolean limitExceeded;
    private int entryCount;
    private long totalUncompressedBytes;
    private int maxNestedDepthSeen;
    private final EnumSet<ArchiveIssue> issues = EnumSet.noneOf(ArchiveIssue.class);

    /** Builds a result representing a file that could not be read/inspected at all. */
    public static JarInspectionResult unreadable(String problem) {
        JarInspectionResult r = new JarInspectionResult();
        r.addProblem(problem);
        return r;
    }

    public boolean structurallyValidZip() {
        return structurallyValidZip;
    }

    void setStructurallyValidZip(boolean v) {
        this.structurallyValidZip = v;
    }

    public Optional<ModMetadata> modMetadata() {
        return Optional.ofNullable(modMetadata);
    }

    void setModMetadata(ModMetadata m) {
        this.modMetadata = m;
    }

    public List<String> manifestAttributes() {
        return manifestAttributes;
    }

    public List<String> nestedJarEntries() {
        return nestedJarEntries;
    }

    public boolean hasSignatureEntries() {
        return hasSignatureEntries;
    }

    void setHasSignatureEntries(boolean v) {
        this.hasSignatureEntries = v;
    }

    public boolean doubleExtension() {
        return doubleExtension;
    }

    void setDoubleExtension(boolean v) {
        this.doubleExtension = v;
    }

    public List<String> traversalEntryNames() {
        return traversalEntryNames;
    }

    public List<String> problems() {
        return problems;
    }

    /** A generic problem. Prefer the typed helpers below where the category is known. */
    void addProblem(String p) {
        problems.add(p);
    }

    /** Records a malformed-archive problem (bad ZIP structure or a failed entry). */
    void addMalformed(String p) {
        problems.add(p);
        issues.add(ArchiveIssue.MALFORMED);
    }

    /** Records an unsupported-feature problem (e.g. an encrypted or spanned member). */
    void addUnsupported(String p) {
        problems.add(p);
        issues.add(ArchiveIssue.UNSUPPORTED_FEATURE);
    }

    void addTraversalEntry(String name) {
        traversalEntryNames.add(name);
        issues.add(ArchiveIssue.TRAVERSAL_ENTRY);
    }

    /** The categorised set of issues found. */
    public Set<ArchiveIssue> issues() {
        return issues;
    }

    public boolean isMalformed() {
        return issues.contains(ArchiveIssue.MALFORMED);
    }

    public boolean hasTraversalEntries() {
        return issues.contains(ArchiveIssue.TRAVERSAL_ENTRY);
    }

    public boolean hasUnsupportedFeature() {
        return issues.contains(ArchiveIssue.UNSUPPORTED_FEATURE);
    }

    public boolean limitExceeded() {
        return limitExceeded;
    }

    void setLimitExceeded(boolean v) {
        this.limitExceeded = v;
        if (v) {
            issues.add(ArchiveIssue.LIMIT_EXCEEDED);
        }
    }

    /**
     * SecuroGuard never establishes signer trust. The presence of signature-related
     * entries ({@link #hasSignatureEntries()}) says a JAR <em>claims</em> to be
     * signed; it is not proof the signature is valid or the signer is trusted. This
     * always returns {@code false} in the MVP and exists to make that explicit to
     * callers so no code mistakes "has a .RSA file" for "trusted".
     */
    public boolean signerTrustEstablished() {
        return false;
    }

    public int entryCount() {
        return entryCount;
    }

    void setEntryCount(int c) {
        this.entryCount = c;
    }

    public long totalUncompressedBytes() {
        return totalUncompressedBytes;
    }

    void setTotalUncompressedBytes(long b) {
        this.totalUncompressedBytes = b;
    }

    private long cumulativeArchiveBytes;

    /** Cumulative bytes of nested-archive content loaded into memory this inspection. */
    public long cumulativeArchiveBytes() {
        return cumulativeArchiveBytes;
    }

    void addCumulativeArchiveBytes(long n) {
        this.cumulativeArchiveBytes += n;
    }

    public int maxNestedDepthSeen() {
        return maxNestedDepthSeen;
    }

    void setMaxNestedDepthSeen(int d) {
        this.maxNestedDepthSeen = d;
    }

    /** Convenience: did anything worth a finding turn up? */
    public boolean hasConcerns() {
        return doubleExtension || !traversalEntryNames.isEmpty() || !problems.isEmpty()
                || limitExceeded || !issues.isEmpty();
    }
}
