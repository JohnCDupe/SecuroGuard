package com.securoguard.core.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Streaming SHA-256 helpers. Content is read in bounded chunks; nothing is
 * deserialized or executed. Hashes are lowercase hex, the canonical form used by
 * Modrinth and in the advisory feed.
 */
public final class Hashing {

    private static final int BUFFER = 64 * 1024;

    private Hashing() {
    }

    /** Computes the lowercase-hex SHA-256 of a file's bytes. */
    public static String sha256(Path file) throws IOException {
        return hash(HashAlgorithm.SHA256, file);
    }

    /** Computes the lowercase-hex SHA-256 of an in-memory byte array. */
    public static String sha256(byte[] data) {
        return hash(HashAlgorithm.SHA256, data);
    }

    /** Computes the lowercase-hex SHA-512 of a file's bytes (used for Modrinth lookup). */
    public static String sha512(Path file) throws IOException {
        return hash(HashAlgorithm.SHA512, file);
    }

    /** Computes the lowercase-hex SHA-512 of an in-memory byte array. */
    public static String sha512(byte[] data) {
        return hash(HashAlgorithm.SHA512, data);
    }

    /** A file's SHA-256 plus its captured leading header bytes (for type detection). */
    public record Digest(String sha256, byte[] header, int headerLen) {
    }

    /**
     * Computes SHA-256 <em>and</em> captures the first few bytes in a single pass,
     * so a scanner can hash and classify a file without opening it twice.
     */
    public static Digest sha256AndHeader(Path file) throws IOException {
        MessageDigest md = newDigest(HashAlgorithm.SHA256);
        byte[] header = new byte[8];
        int headerLen = 0;
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[BUFFER];
            int n;
            while ((n = in.read(buf)) != -1) {
                md.update(buf, 0, n);
                if (headerLen < header.length) {
                    int copy = Math.min(n, header.length - headerLen);
                    System.arraycopy(buf, 0, header, headerLen, copy);
                    headerLen += copy;
                }
            }
        }
        return new Digest(HexFormat.of().formatHex(md.digest()), header, headerLen);
    }

    /** Streams a file through the given digest and returns lowercase hex. */
    public static String hash(HashAlgorithm algorithm, Path file) throws IOException {
        MessageDigest digest = newDigest(algorithm);
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buf = new byte[BUFFER];
            int n;
            while ((n = in.read(buf)) != -1) {
                digest.update(buf, 0, n);
            }
        }
        return HexFormat.of().formatHex(digest.digest());
    }

    public static String hash(HashAlgorithm algorithm, byte[] data) {
        return HexFormat.of().formatHex(newDigest(algorithm).digest(data));
    }

    private static MessageDigest newDigest(HashAlgorithm algorithm) {
        try {
            return MessageDigest.getInstance(algorithm.jcaName());
        } catch (NoSuchAlgorithmException e) {
            // These algorithms are mandated by the JLS; absence means a broken JRE.
            throw new IllegalStateException(algorithm.jcaName() + " unavailable", e);
        }
    }
}
