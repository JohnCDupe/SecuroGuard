package com.securoguard.core.baseline;

/**
 * Thrown when a baseline file exists but cannot be trusted (corrupt JSON or an
 * unsupported schema version). Callers should treat this as "no trusted baseline"
 * and typically re-approve, rather than crashing. The offending file is preserved
 * alongside for forensic review; it is never silently overwritten.
 */
public class BaselineException extends Exception {

    public BaselineException(String message) {
        super(message);
    }

    public BaselineException(String message, Throwable cause) {
        super(message, cause);
    }
}
