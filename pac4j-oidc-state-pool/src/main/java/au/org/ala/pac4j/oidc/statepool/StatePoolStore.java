package au.org.ala.pac4j.oidc.statepool;

import org.pac4j.core.context.CallContext;

/**
 * Backing store for the OIDC {@code state} pool.
 *
 * <p>{@link #consume} MUST be an atomic find-and-remove: exactly one concurrent caller per
 * (clientName, stateValue) may observe "present and now removed".</p>
 *
 * <p>Shipped implementations: {@link SessionStatePoolStore} (single-JVM / sticky sessions) and
 * a MongoDB-backed store in {@code au.org.ala:pac4j-oidc-state-pool-mongodb} (non-sticky
 * clusters).</p>
 *
 * <p>Implementations own TTL/expiry and bound enforcement; the pool passes the configured
 * {@code ttlMillis}/{@code maxSize} through. All methods take {@link CallContext} and client
 * name explicitly, so a single instance is shareable.</p>
 */
public interface StatePoolStore {

    /**
     * Persist a newly generated state.
     *
     * @param ctx        the current call context
     * @param clientName the OIDC client name (namespaces the pool)
     * @param stateValue the state value to record
     * @param ttlMillis  state validity in milliseconds
     * @param maxSize    maximum concurrent states kept (LRU eviction beyond this)
     */
    void add(CallContext ctx, String clientName, String stateValue, long ttlMillis, int maxSize);

    /**
     * Atomically find and remove a state (one-time use).
     *
     * <p>Removing the state MUST NOT remove the {@code flowSecrets[state]} association: pac4j's
     * callback consumes the state first, then retrieves the PKCE {@code code_verifier} and
     * validates the {@code nonce} keyed by the same state. The association has an independent
     * lifecycle — {@link #consumeCodeVerifier} / {@link #consumeNonce} /
     * {@link #consumeNonceByValue} remove individual secrets; TTL/LRU sweep expires abandoned
     * associations.</p>
     *
     * @param ctx        the current call context
     * @param clientName the OIDC client name
     * @param stateValue the state value to consume
     * @param ttlMillis  entries older than this are treated as absent
     * @return {@code true} iff the entry existed, was unexpired and is now removed
     */
    boolean consume(CallContext ctx, String clientName, String stateValue, long ttlMillis);

    /*
     * Per-flow secret associations (PKCE code_verifier and nonce), keyed by the echoed state.
     * Shipped as default methods so external stores written against v1 keep compiling.
     * A deployment relying on PKCE pooling (on by default) or nonce pooling (opt-in) MUST
     * override them — the defaults silently disable both features.
     */

    /**
     * Record the PKCE code_verifier and/or nonce for a pooled state. Called on the redirect
     * side after the state has been added. {@code null} arguments leave the existing value
     * untouched. Associations share the pool's TTL/bound and survive state consumption.
     */
    default void addFlowSecrets(CallContext ctx, String clientName, String stateValue,
                                String codeVerifier, String nonce, long ttlMillis, int maxSize) {
        // no-op: stores predating these methods silently disable PKCE/nonce pooling
    }

    /**
     * Atomically find and remove the PKCE code_verifier associated with the given state
     * (one-time use). Sibling secrets (e.g. a nonce) are left intact.
     *
     * @return the verifier, or empty if no live association carries one
     */
    default java.util.Optional<String> consumeCodeVerifier(CallContext ctx, String clientName,
                                                           String stateValue, long ttlMillis) {
        return java.util.Optional.empty();
    }

    /**
     * Atomically find and remove the nonce associated with the given state (one-time use).
     *
     * @return the nonce, or empty if no live association carries one
     */
    default java.util.Optional<String> consumeNonce(CallContext ctx, String clientName,
                                                    String stateValue, long ttlMillis) {
        return java.util.Optional.empty();
    }

    /**
     * Whether the nonce value appears in any live association for this client. Used by nonce
     * pooling to fail closed on an unknown claimed nonce before consuming.
     */
    default boolean containsNonce(CallContext ctx, String clientName, String nonceValue, long ttlMillis) {
        return false;
    }

    /**
     * Atomically find the association whose nonce equals {@code nonceValue} and remove the nonce
     * (one-time use). The consume half of {@link #containsNonce} for nonce pooling, where the
     * flow is correlated by the nonce claim itself rather than by an echoed state.
     */
    default boolean consumeNonceByValue(CallContext ctx, String clientName, String nonceValue, long ttlMillis) {
        return false;
    }
}
