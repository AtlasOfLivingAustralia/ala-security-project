package au.org.ala.pac4j.oidc.statepool;

import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.TechnicalException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Default {@link StatePoolStore}: persists the pool in the pac4j {@link SessionStore} and makes
 * {@link #consume} atomic <em>within a single JVM</em> via a static stripe lock table indexed by
 * the session id.
 *
 * <p>Session-id resolution: mutating operations force id creation ({@code getSessionId(true)})
 * before picking the stripe; after acquiring the stripe the id is re-read and, if it changed
 * (session rotation), the stripe is released and retried, bounded by {@link #MAX_LOCK_RETRIES}.
 * If the id never stabilises the operation fails closed with a {@link TechnicalException} while
 * holding no lock. A session-less store shares one static sentinel stripe. A store that rotates
 * an already-serialized attribute concurrently with an in-flight consume cannot be synchronised
 * against — do not renew sessions during an OIDC callback.</p>
 *
 * <p>Correct for single-node and sticky-session clusters only. For non-sticky /
 * replicated-session clusters use a store with a native atomic compare-and-delete (e.g. the
 * MongoDB-backed implementation in {@code pac4j-oidc-state-pool-mongodb}).</p>
 *
 * <p>The pool is stored as a {@link StatePoolHolder} so Java-serialization-based session stores
 * can persist it. The stripe table is {@code static} and is never serialized. This class is
 * stateless per request and safe to share JVM-wide.</p>
 */
public class SessionStatePoolStore implements StatePoolStore {

    /** Suffix appended to the client name to build the session attribute key. */
    public static final String STATE_POOL_SUFFIX = "$statePool";

    /** Number of lock stripes; fixed at class-load time so the table is strictly bounded. */
    private static final int LOCK_STRIPES = 1024;

    /**
     * Retry budget for session-id rotation under the lock. When exhausted without a stable id,
     * the caller fails closed by throwing a {@link TechnicalException} while holding no lock —
     * see {@link #acquireSessionLock}.
     */
    private static final int MAX_LOCK_RETRIES = 4;

    /**
     * Fixed-size stripe lock table. {@code static} so all store/pool instances in this JVM
     * contend on the same locks for the same session.
     */
    private static final ReentrantLock[] LOCK_STRIPES_TABLE = new ReentrantLock[LOCK_STRIPES];

    /**
     * Sentinel lock used when the session id is unavailable (stateless session store). Every
     * absent-id caller in this JVM contends on this one stripe.
     */
    private static final ReentrantLock ABSENT_ID_SENTINEL = new ReentrantLock();

    static {
        for (int i = 0; i < LOCK_STRIPES; i++) {
            LOCK_STRIPES_TABLE[i] = new ReentrantLock();
        }
    }

    /** {@inheritDoc} */
    @Override
    public void add(final CallContext ctx, final String clientName, final String stateValue,
                    final long ttlMillis, final int maxSize) {
        if (stateValue == null || stateValue.isBlank()) {
            return;
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ true);
        try {
            final LinkedHashMap<String, Long> pool = readPool(ctx, key);
            // Read associations too so a state re-add does not drop a sibling flow's secrets.
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            pool.remove(stateValue);
            pool.put(stateValue, System.currentTimeMillis());
            sweepExpired(pool, ttlMillis);
            sweepExpiredSecrets(secrets, ttlMillis);
            evictOverflow(pool, maxSize);
            evictOverflowSecrets(secrets, maxSize);
            betweenReadAndWrite();
            writePool(ctx, key, pool, secrets);
        } finally {
            sessionLock.release();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean consume(final CallContext ctx, final String clientName, final String stateValue,
                           final long ttlMillis) {
        if (stateValue == null || stateValue.isBlank()) {
            return false;
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ false);
        try {
            final LinkedHashMap<String, Long> pool = readPool(ctx, key);
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            sweepExpired(pool, ttlMillis);
            sweepExpiredSecrets(secrets, ttlMillis);
            // Remove ONLY the state. The flowSecrets association must survive state consumption:
            // pac4j's callback consumes the state first, then reads the PKCE verifier and
            // validates the nonce keyed by the same state. Associations are removed individually
            // by consumeCodeVerifier/consumeNonce(ByValue) or aged out by TTL/LRU.
            final Long timestamp = pool.remove(stateValue);
            betweenReadAndWrite();
            writePool(ctx, key, pool, secrets);
            return timestamp != null;
        } finally {
            sessionLock.release();
        }
    }

    /** {@inheritDoc} */
    @Override
    public void addFlowSecrets(final CallContext ctx, final String clientName, final String stateValue,
                               final String codeVerifier, final String nonce,
                               final long ttlMillis, final int maxSize) {
        if (stateValue == null || stateValue.isBlank()) {
            return;
        }
        if (codeVerifier == null && nonce == null) {
            return;
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ true);
        try {
            final LinkedHashMap<String, Long> pool = readPool(ctx, key);
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            sweepExpired(pool, ttlMillis);
            sweepExpiredSecrets(secrets, ttlMillis);
            // remove-then-put refreshes LRU order, as for the pool entries.
            final FlowSecrets existing = secrets.remove(stateValue);
            final String mergedVerifier = codeVerifier != null ? codeVerifier
                : (existing == null ? null : existing.getCodeVerifier());
            final String mergedNonce = nonce != null ? nonce
                : (existing == null ? null : existing.getNonce());
            secrets.put(stateValue, new FlowSecrets(mergedVerifier, mergedNonce, System.currentTimeMillis()));
            evictOverflowSecrets(secrets, maxSize);
            betweenReadAndWrite();
            writePool(ctx, key, pool, secrets);
        } finally {
            sessionLock.release();
        }
    }

    /** {@inheritDoc} */
    @Override
    public Optional<String> consumeCodeVerifier(final CallContext ctx, final String clientName,
                                                final String stateValue, final long ttlMillis) {
        if (stateValue == null || stateValue.isBlank()) {
            return Optional.empty();
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ false);
        try {
            final LinkedHashMap<String, Long> pool = readPool(ctx, key);
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            sweepExpired(pool, ttlMillis);
            sweepExpiredSecrets(secrets, ttlMillis);
            // Clear ONLY the verifier; a pending nonce on the same entry must survive for the
            // profile-creator step that follows the authenticator.
            final FlowSecrets entry = secrets.get(stateValue);
            if (entry == null || entry.getCodeVerifier() == null) {
                // Pure consume: whether an empty result fails closed or falls back to the raw
                // session slot is the caller's decision.
                return Optional.empty();
            }
            final String verifier = entry.getCodeVerifier();
            // FlowSecrets is immutable: replace the map entry so a failed writePool leaves the
            // session-held copy unchanged (fail-closed).
            final FlowSecrets updated = entry.withoutCodeVerifier();
            if (updated.isEmpty()) {
                secrets.remove(stateValue);
            } else {
                secrets.put(stateValue, updated);
            }
            betweenReadAndWrite();
            writePool(ctx, key, pool, secrets);
            return Optional.of(verifier);
        } finally {
            sessionLock.release();
        }
    }

    /** {@inheritDoc} */
    @Override
    public Optional<String> consumeNonce(final CallContext ctx, final String clientName,
                                         final String stateValue, final long ttlMillis) {
        if (stateValue == null || stateValue.isBlank()) {
            return Optional.empty();
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ false);
        try {
            final LinkedHashMap<String, Long> pool = readPool(ctx, key);
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            sweepExpired(pool, ttlMillis);
            sweepExpiredSecrets(secrets, ttlMillis);
            final FlowSecrets entry = secrets.get(stateValue);
            if (entry == null || entry.getNonce() == null) {
                return Optional.empty();
            }
            final String nonce = entry.getNonce();
            final FlowSecrets updated = entry.withoutNonce();
            if (updated.isEmpty()) {
                secrets.remove(stateValue);
            } else {
                secrets.put(stateValue, updated);
            }
            betweenReadAndWrite();
            writePool(ctx, key, pool, secrets);
            return Optional.of(nonce);
        } finally {
            sessionLock.release();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean containsNonce(final CallContext ctx, final String clientName,
                                 final String nonceValue, final long ttlMillis) {
        if (nonceValue == null || nonceValue.isBlank()) {
            return false;
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ false);
        try {
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            sweepExpiredSecrets(secrets, ttlMillis);
            return secrets.values().stream().anyMatch(s -> nonceValue.equals(s.getNonce()));
        } finally {
            sessionLock.release();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean consumeNonceByValue(final CallContext ctx, final String clientName,
                                       final String nonceValue, final long ttlMillis) {
        if (nonceValue == null || nonceValue.isBlank()) {
            return false;
        }
        final String key = sessionKeyFor(clientName);
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ false);
        try {
            final LinkedHashMap<String, Long> pool = readPool(ctx, key);
            final LinkedHashMap<String, FlowSecrets> secrets = readSecrets(ctx, key);
            sweepExpired(pool, ttlMillis);
            sweepExpiredSecrets(secrets, ttlMillis);
            // Nonce pooling correlates by the nonce claim itself (no usable state is available
            // at that point), so find the entry carrying this exact nonce value.
            for (final var it = secrets.entrySet().iterator(); it.hasNext(); ) {
                final Map.Entry<String, FlowSecrets> candidate = it.next();
                final FlowSecrets entry = candidate.getValue();
                if (nonceValue.equals(entry.getNonce())) {
                    final FlowSecrets updated = entry.withoutNonce();
                    if (updated.isEmpty()) {
                        it.remove();
                    } else {
                        candidate.setValue(updated);
                    }
                    betweenReadAndWrite();
                    writePool(ctx, key, pool, secrets);
                    return true;
                }
            }
            return false;
        } finally {
            sessionLock.release();
        }
    }

    /**
     * No-op hook invoked inside the critical section, between reading the pool and writing it
     * back, so tests can widen the race window. Production behaviour is unaffected.
     */
    protected void betweenReadAndWrite() {
        // no-op
    }

    /* internals */

    /**
     * A session lock plus the session id it was acquired for, so tests can observe which id was
     * actually locked. {@code sessionId} is {@code null} iff the sentinel stripe is held.
     */
    private static final class SessionLock {
        private final ReentrantLock lock;
        private final String sessionId;

        private SessionLock(final ReentrantLock lock, final String sessionId) {
            this.lock = lock;
            this.sessionId = sessionId;
        }

        private void release() {
            lock.unlock();
        }
    }

    /**
     * Acquire the stripe lock for the current session: resolve id, lock, re-resolve id, retry on
     * change (session rotation), bounded by {@link #MAX_LOCK_RETRIES}.
     *
     * <p>Fail closed on exhaustion: if the id has not stabilised, the stripe held cannot be
     * proven to match what other callers for this session will pick, so a
     * {@link TechnicalException} is thrown while holding no lock, before any pool state is
     * touched.</p>
     *
     * @param createIfAbsent {@code true} for mutating operations so a session id is forced into
     *                       existence before the stripe is picked
     * @return the held lock plus the session id that was locked (or {@code null} for the sentinel)
     * @throws TechnicalException if the id could not be stabilised within the retry budget
     */
    private SessionLock acquireSessionLock(final CallContext ctx, final boolean createIfAbsent) {
        String sessionId = resolveSessionId(ctx, createIfAbsent);
        for (int attempt = 0; attempt < MAX_LOCK_RETRIES; attempt++) {
            final ReentrantLock lock = lockFor(sessionId);
            lock.lock();
            final String currentId = resolveSessionId(ctx, createIfAbsent);
            if (idsMatch(sessionId, currentId)) {
                return new SessionLock(lock, sessionId);
            }
            lock.unlock();
            sessionId = currentId;
        }
        // Id never stabilised: no stripe choice is provably right. The last acquired stripe was
        // released at the end of the final iteration, so we hold no lock here and no pool state
        // has been read or written.
        throw new TechnicalException(
            "SessionStatePoolStore: session id could not be stabilized after "
                + MAX_LOCK_RETRIES + " attempts; refusing to touch pool state under an "
                + "unverified lock stripe. This indicates a misbehaving SessionStore that "
                + "rotates the session id on every read (last observed id: " + sessionId + ").");
    }

    /** Two {@code null}s match (both mean "sentinel"); a {@code null} and a real id do not. */
    private static boolean idsMatch(final String a, final String b) {
        if (a == null) {
            return b == null;
        }
        return a.equals(b);
    }

    /** Absent-id callers all share {@link #ABSENT_ID_SENTINEL}. */
    private static ReentrantLock lockFor(final String sessionId) {
        if (sessionId == null) {
            return ABSENT_ID_SENTINEL;
        }
        return LOCK_STRIPES_TABLE[Math.floorMod(sessionId.hashCode(), LOCK_STRIPES)];
    }

    /**
     * Resolve the current session id, or {@code null} if none is available.
     *
     * @param createIfAbsent {@code true} to create the session (and id) if none exists — used on
     *                       the mutating path; {@code false} on the read/consume path
     */
    private static String resolveSessionId(final CallContext ctx, final boolean createIfAbsent) {
        final WebContext webContext = ctx.webContext();
        final SessionStore sessionStore = ctx.sessionStore();
        if (webContext == null || sessionStore == null) {
            return null;
        }
        final Optional<String> id = sessionStore.getSessionId(webContext, createIfAbsent);
        if (id.isEmpty() || id.get().isBlank()) {
            return null;
        }
        return id.get();
    }

    private void sweepExpired(final Map<String, Long> pool, final long ttlMillis) {
        final long now = System.currentTimeMillis();
        pool.values().removeIf(timestamp -> now - timestamp > ttlMillis);
    }

    private void sweepExpiredSecrets(final Map<String, FlowSecrets> secrets, final long ttlMillis) {
        final long now = System.currentTimeMillis();
        secrets.values().removeIf(s -> now - s.getCreatedAt() > ttlMillis);
    }

    private void evictOverflow(final LinkedHashMap<String, Long> pool, final int maxSize) {
        while (pool.size() > maxSize) {
            final Map.Entry<String, Long> eldest = pool.entrySet().iterator().next();
            pool.remove(eldest.getKey());
        }
    }

    private void evictOverflowSecrets(final LinkedHashMap<String, FlowSecrets> secrets, final int maxSize) {
        while (secrets.size() > maxSize) {
            final Map.Entry<String, FlowSecrets> eldest = secrets.entrySet().iterator().next();
            secrets.remove(eldest.getKey());
        }
    }

    private LinkedHashMap<String, Long> readPool(final CallContext ctx, final String key) {
        final SessionStore sessionStore = ctx.sessionStore();
        final Optional<Object> holder = sessionStore.get(ctx.webContext(), key);
        if (holder.isPresent() && holder.get() instanceof StatePoolHolder poolHolder) {
            return new LinkedHashMap<>(poolHolder.getEntries());
        }
        return new LinkedHashMap<>();
    }

    private LinkedHashMap<String, FlowSecrets> readSecrets(final CallContext ctx, final String key) {
        final SessionStore sessionStore = ctx.sessionStore();
        final Optional<Object> holder = sessionStore.get(ctx.webContext(), key);
        if (holder.isPresent() && holder.get() instanceof StatePoolHolder poolHolder) {
            // getFlowSecrets() lazily upgrades a v1-deserialized holder whose field is null.
            return new LinkedHashMap<>(poolHolder.getFlowSecrets());
        }
        return new LinkedHashMap<>();
    }

    /**
     * Persist pool entries and flow-secret associations as ONE holder, so the two maps cannot
     * diverge across a read-modify-write cycle. The ONLY write path — every mutation writes both
     * maps together.
     */
    private void writePool(final CallContext ctx, final String key, final LinkedHashMap<String, Long> pool,
                           final LinkedHashMap<String, FlowSecrets> secrets) {
        ctx.sessionStore().set(ctx.webContext(), key, new StatePoolHolder(pool, secrets));
    }

    /** Session attribute key for a given client. */
    public static String sessionKeyFor(final String clientName) {
        return clientName + STATE_POOL_SUFFIX;
    }

    /**
     * Current pool size for a client, read under the session's stripe lock so it observes a
     * consistent snapshot. Read-only: does not create a session just to lock.
     */
    public Optional<Integer> size(final CallContext ctx, final String clientName) {
        final SessionLock sessionLock = acquireSessionLock(ctx, /* createIfAbsent = */ false);
        try {
            return ctx.sessionStore().get(ctx.webContext(), sessionKeyFor(clientName))
                .filter(StatePoolHolder.class::isInstance)
                .map(StatePoolHolder.class::cast)
                .map(holder -> holder.getEntries().size());
        } finally {
            sessionLock.release();
        }
    }
}
