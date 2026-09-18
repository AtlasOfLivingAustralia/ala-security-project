package au.org.ala.pac4j.oidc.statepool;

import org.pac4j.core.context.CallContext;

import java.util.Objects;
import java.util.Optional;

/**
 * Stateless helper for the OIDC concurrent-state pool.
 *
 * <p>Holds only the pool's configuration (TTL, bound, store) and funnels every operation to the
 * configured {@link StatePoolStore}, passing {@link CallContext} and client name explicitly.
 * Isolation is per-session/per-client-name inside the store, so one instance is shareable across
 * the JVM and across clients.</p>
 */
public final class StatePool {

    /** Default state TTL (5 minutes). */
    public static final long DEFAULT_TTL_MILLIS = 5L * 60L * 1000L;
    /** Default maximum concurrent states kept per session (LRU eviction beyond). */
    public static final int DEFAULT_MAX_SIZE = 20;

    private final StatePoolStore store;
    private final long ttlMillis;
    private final int maxSize;

    /**
     * Create a pool with default TTL and bound, backed by a new {@link SessionStatePoolStore}.
     */
    public StatePool() {
        this(new SessionStatePoolStore(), DEFAULT_TTL_MILLIS, DEFAULT_MAX_SIZE);
    }

    /**
     * Create a pool backed by a new {@link SessionStatePoolStore}.
     */
    public StatePool(final long ttlMillis, final int maxSize) {
        this(new SessionStatePoolStore(), ttlMillis, maxSize);
    }

    /**
     * Create a pool.
     */
    public StatePool(final StatePoolStore store, final long ttlMillis, final int maxSize) {
        this.store = Objects.requireNonNull(store, "store must not be null");
        if (ttlMillis <= 0) {
            throw new IllegalArgumentException("ttlMillis must be positive");
        }
        if (maxSize <= 0) {
            throw new IllegalArgumentException("maxSize must be positive");
        }
        this.ttlMillis = ttlMillis;
        this.maxSize = maxSize;
    }

    /**
     * Record a newly generated state.
     */
    public void add(final CallContext ctx, final String clientName, final String stateValue) {
        store.add(ctx, requireClientName(clientName), stateValue, ttlMillis, maxSize);
    }

    /**
     * Atomically consume (find-and-remove) a state.
     *
     * @return whether the state was present, unexpired and is now consumed
     */
    public boolean consume(final CallContext ctx, final String clientName, final String stateValue) {
        return store.consume(ctx, requireClientName(clientName), stateValue, ttlMillis);
    }

    /**
     * Record the PKCE code_verifier and/or nonce for a pooled flow, keyed by state. Called on
     * the redirect side after {@link #add}. {@code null} leaves the existing value untouched.
     */
    public void addFlowSecrets(final CallContext ctx, final String clientName, final String stateValue,
                               final String codeVerifier, final String nonce) {
        store.addFlowSecrets(ctx, requireClientName(clientName), stateValue, codeVerifier, nonce,
            ttlMillis, maxSize);
    }

    /**
     * Atomically consume the PKCE code_verifier for a state (one-time use; a sibling nonce is
     * left intact).
     *
     * @return the verifier, or empty if no live association carries one
     */
    public Optional<String> consumeCodeVerifier(final CallContext ctx, final String clientName,
                                                final String stateValue) {
        return store.consumeCodeVerifier(ctx, requireClientName(clientName), stateValue, ttlMillis);
    }

    /**
     * Atomically consume the nonce for a state (one-time use).
     *
     * @return the nonce, or empty if no live association carries one
     */
    public Optional<String> consumeNonce(final CallContext ctx, final String clientName,
                                         final String stateValue) {
        return store.consumeNonce(ctx, requireClientName(clientName), stateValue, ttlMillis);
    }

    /**
     * Whether the nonce value appears in any live association for this client.
     */
    public boolean containsNonce(final CallContext ctx, final String clientName, final String nonceValue) {
        return store.containsNonce(ctx, requireClientName(clientName), nonceValue, ttlMillis);
    }

    /**
     * Atomically consume the association whose nonce equals the given value (one-time use).
     * Used by nonce pooling, where the profile creator correlates by the nonce claim rather
     * than by an echoed state.
     *
     * @return {@code true} iff a live association carried this nonce and it is now removed
     */
    public boolean consumeNonceByValue(final CallContext ctx, final String clientName, final String nonceValue) {
        return store.consumeNonceByValue(ctx, requireClientName(clientName), nonceValue, ttlMillis);
    }

    /**
     * Current pool size for a client, if the store supports reporting it.
     */
    public Optional<Integer> size(final CallContext ctx, final String clientName) {
        if (store instanceof SessionStatePoolStore sessionStore) {
            return sessionStore.size(ctx, requireClientName(clientName));
        }
        return Optional.empty();
    }

    /**
     * The backing store.
     */
    public StatePoolStore getStore() {
        return store;
    }

    private static String requireClientName(final String clientName) {
        if (clientName == null || clientName.isBlank()) {
            throw new IllegalArgumentException("clientName cannot be blank");
        }
        return clientName;
    }
}
