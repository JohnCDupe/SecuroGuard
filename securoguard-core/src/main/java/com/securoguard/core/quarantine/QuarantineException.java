package com.securoguard.core.quarantine;

/**
 * Raised when a quarantine or restore operation cannot be completed safely. When
 * this is thrown, SecuroGuard has taken care to leave the user's files in a
 * consistent state — in particular the original file is never deleted unless its
 * quarantined copy was verified byte-for-byte.
 */
public class QuarantineException extends Exception {

    public QuarantineException(String message) {
        super(message);
    }

    public QuarantineException(String message, Throwable cause) {
        super(message, cause);
    }
}
