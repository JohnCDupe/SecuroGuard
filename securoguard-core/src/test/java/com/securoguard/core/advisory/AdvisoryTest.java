package com.securoguard.core.advisory;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AdvisoryTest {

    @Test
    void versionComparisonHandlesDottedAndPreRelease() {
        assertTrue(Version.parse("1.2.0").compareTo(Version.parse("1.10.0")) < 0);
        assertTrue(Version.parse("0.19.0").compareTo(Version.parse("0.18.9")) > 0);
        assertEquals(0, Version.parse("1.21.11").compareTo(Version.parse("1.21.11")));
        // Build metadata after '+' is ignored.
        assertEquals(0, Version.parse("0.19.0+1.21").compareTo(Version.parse("0.19.0")));
        // Pre-release ranks below the release.
        assertTrue(Version.parse("1.0.0-beta").compareTo(Version.parse("1.0.0")) < 0);
    }

    @Test
    void versionRangeIsHalfOpen() {
        VersionRange r = new VersionRange("0.0.0", "0.19.0");
        assertTrue(r.contains(Version.parse("0.18.9")));
        assertFalse(r.contains(Version.parse("0.19.0")), "fixed bound is exclusive");
        assertTrue(VersionRange.any().containsRaw("1.0.0"));
        // A malformed version is a safe non-match, never treated as 0.
        assertFalse(VersionRange.any().containsRaw("not-a-version"));
        assertTrue(Version.tryParse("not-a-version").isEmpty());
    }

    @Test
    void matcherMatchesAffectedModCoordinates() {
        AdvisoryFeed feed = AdvisoryFeeds.bundledFeed();
        AdvisoryMatcher matcher = new AdvisoryMatcher(feed);

        // Vulnerable Litematica version on Fabric (MC 1.21.11, patched at 0.26.11).
        List<Advisory> hits = matcher.match(new AdvisoryMatcher.Query(
                "litematica", "fabric", "1.21.11", "0.26.10", null));
        assertEquals(1, hits.size());

        // The fixed version must NOT match.
        assertTrue(matcher.match(new AdvisoryMatcher.Query(
                "litematica", "fabric", "1.21.11", "0.26.11", null)).isEmpty());

        // A different Minecraft line matches its own advisory/boundary (1.21.4 -> 0.21.7).
        assertEquals(1, matcher.match(new AdvisoryMatcher.Query(
                "litematica", "fabric", "1.21.4", "0.21.6", null)).size());
        assertTrue(matcher.match(new AdvisoryMatcher.Query(
                "litematica", "fabric", "1.21.4", "0.21.7", null)).isEmpty());

        // Unrelated mod must not match.
        assertTrue(matcher.match(new AdvisoryMatcher.Query(
                "sodium", "fabric", "1.21.11", "0.5.0", null)).isEmpty());
    }

    @Test
    void ed25519SignatureVerifies() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] feed = AdvisoryFeeds.bundledFeedBytes();

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(kp.getPrivate());
        signer.update(feed);
        byte[] signature = signer.sign();

        assertTrue(AdvisoryFeedVerifier.verify(feed, signature, kp.getPublic()),
                "a genuine signature over the exact feed bytes must verify");
    }

    @Test
    void tamperedFeedFailsVerification() throws Exception {
        KeyPair kp = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] feed = AdvisoryFeeds.bundledFeedBytes();

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(kp.getPrivate());
        signer.update(feed);
        byte[] signature = signer.sign();

        byte[] tampered = "{\"schemaVersion\":1,\"advisories\":[]}".getBytes(StandardCharsets.UTF_8);
        assertFalse(AdvisoryFeedVerifier.verify(tampered, signature, kp.getPublic()),
                "a signature must not validate different bytes");
    }

    @Test
    void wrongKeyFailsVerification() throws Exception {
        KeyPair signingKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        KeyPair otherKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] feed = AdvisoryFeeds.bundledFeedBytes();

        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(signingKey.getPrivate());
        signer.update(feed);
        byte[] signature = signer.sign();

        assertFalse(AdvisoryFeedVerifier.verify(feed, signature, otherKey.getPublic()),
                "verifying against a different pinned key must fail");
    }
}
