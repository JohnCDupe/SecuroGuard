package com.securoguard.core.util;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Explicit hash-algorithm identity so callers never pass an ambiguous string like
 * {@code "sha256"} around. Each constant knows its JCA name, its lowercase-hex
 * length, and how to validate a hex string of that algorithm.
 *
 * <p>Why this matters here: SecuroGuard uses SHA-256 as its internal evidence and
 * quarantine-integrity hash, but Modrinth's version-file lookup only supports
 * {@code sha1} and {@code sha512} — so the reputation path must speak SHA-512
 * explicitly. Making the algorithm a type prevents mixing them up.
 */
public enum HashAlgorithm {
    SHA1("SHA-1", "sha1", 40),
    SHA256("SHA-256", "sha256", 64),
    SHA512("SHA-512", "sha512", 128);

    private final String jcaName;
    private final String queryName;
    private final int hexLength;
    private final Pattern hexPattern;

    HashAlgorithm(String jcaName, String queryName, int hexLength) {
        this.jcaName = jcaName;
        this.queryName = queryName;
        this.hexLength = hexLength;
        this.hexPattern = Pattern.compile("^[0-9a-f]{" + hexLength + "}$");
    }

    /** The JCA {@code MessageDigest} algorithm name (e.g. "SHA-512"). */
    public String jcaName() {
        return jcaName;
    }

    /** The lowercase identifier used in APIs / query strings (e.g. "sha512"). */
    public String queryName() {
        return queryName;
    }

    public int hexLength() {
        return hexLength;
    }

    /** True if {@code hex} is a well-formed lowercase-hex digest of this algorithm. */
    public boolean isValidHex(String hex) {
        return hex != null && hexPattern.matcher(hex.toLowerCase(Locale.ROOT)).matches();
    }
}
