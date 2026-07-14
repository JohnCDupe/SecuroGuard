package com.securoguard.core.advisory;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Verifies an Ed25519 signature over the raw bytes of an advisory feed using a
 * <em>pinned</em> public key. The intent is that a future signed feed is trusted
 * only if it was signed by SecuroGuard's maintainers; an attacker who tampers with
 * a downloaded feed, or serves their own, cannot forge a valid signature without
 * the private key.
 *
 * <p>Ed25519 is provided natively by the JDK (15+), so no third-party crypto
 * dependency is needed. Verification is fail-closed: any error is treated as an
 * invalid signature.
 */
public final class AdvisoryFeedVerifier {

    private static final String ALGORITHM = "Ed25519";

    private AdvisoryFeedVerifier() {
    }

    /**
     * @param feedBytes the exact bytes that were signed (the feed JSON as served)
     * @param signature the detached Ed25519 signature
     * @param publicKey the pinned verifying key
     * @return true iff the signature is valid for these bytes and key
     */
    public static boolean verify(byte[] feedBytes, byte[] signature, PublicKey publicKey) {
        try {
            Signature verifier = Signature.getInstance(ALGORITHM);
            verifier.initVerify(publicKey);
            verifier.update(feedBytes);
            return verifier.verify(signature);
        } catch (GeneralSecurityException e) {
            // Fail closed: an unverifiable feed is treated as untrusted.
            return false;
        }
    }

    /** Convenience overload taking a base64 detached signature. */
    public static boolean verify(byte[] feedBytes, String base64Signature, PublicKey publicKey) {
        try {
            return verify(feedBytes, Base64.getDecoder().decode(base64Signature), publicKey);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Parses an X.509 (SubjectPublicKeyInfo) DER-encoded Ed25519 public key. */
    public static PublicKey publicKeyFromDer(byte[] der) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
        return kf.generatePublic(new X509EncodedKeySpec(der));
    }

    /** Parses a base64-encoded X.509 Ed25519 public key (the pinned-key format). */
    public static PublicKey publicKeyFromBase64(String base64) throws GeneralSecurityException {
        return publicKeyFromDer(Base64.getDecoder().decode(base64));
    }
}
