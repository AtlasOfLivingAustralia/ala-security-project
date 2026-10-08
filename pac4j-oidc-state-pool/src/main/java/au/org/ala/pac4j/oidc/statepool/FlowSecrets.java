package au.org.ala.pac4j.oidc.statepool;

import java.io.Serializable;

/**
 * Per-flow secrets associated with one pooled {@code state}: the PKCE {@code code_verifier}
 * and/or the {@code nonce} generated for the redirect that produced that state. Keyed by the
 * state's value (the correlation key echoed back on the callback; only {@code code} and
 * {@code state} are echoed, so the state is the only usable key).
 *
 * <p>Immutable: the store consumes a secret by REPLACING the map entry with a {@code without*}
 * copy, so a failed {@code sessionStore.set(...)} cannot leave the session-held instance
 * half-consumed.</p>
 */
public final class FlowSecrets implements Serializable {

    /** Shape (two nullable strings + a long) is unchanged from v1, so this stays {@code 1L}. */
    private static final long serialVersionUID = 1L;

    /** {@code null} when PKCE was not active or the verifier has already been consumed. */
    private final String codeVerifier;

    /** {@code null} when nonce pooling is off or the nonce has already been consumed. */
    private final String nonce;

    /** Insertion epoch-millis; mirrors the owning pool entry's timestamp and drives the TTL
     *  sweep for the association map. */
    private final long createdAt;

    /**
     * Create a secrets record. Either secret may be {@code null}.
     */
    public FlowSecrets(final String codeVerifier, final String nonce, final long createdAt) {
        this.codeVerifier = codeVerifier;
        this.nonce = nonce;
        this.createdAt = createdAt;
    }

    /** The PKCE code_verifier, or {@code null} if absent/consumed. */
    public String getCodeVerifier() {
        return codeVerifier;
    }

    /**
     * A copy with the verifier cleared (one-time-use consume); nonce and timestamp preserved.
     * The store REPLACES the map entry with this copy rather than mutating in place.
     */
    public FlowSecrets withoutCodeVerifier() {
        return new FlowSecrets(null, nonce, createdAt);
    }

    /** The nonce, or {@code null} if absent/consumed. */
    public String getNonce() {
        return nonce;
    }

    /**
     * A copy with the nonce cleared (one-time-use consume); verifier and timestamp preserved.
     * See {@link #withoutCodeVerifier()} for the atomicity rationale.
     */
    public FlowSecrets withoutNonce() {
        return new FlowSecrets(codeVerifier, null, createdAt);
    }

    /** Insertion timestamp (epoch-millis). */
    public long getCreatedAt() {
        return createdAt;
    }

    /**
     * Whether both secrets are gone (never set or already consumed); an empty record's entry can
     * be dropped from the map.
     */
    public boolean isEmpty() {
        return codeVerifier == null && nonce == null;
    }
}
