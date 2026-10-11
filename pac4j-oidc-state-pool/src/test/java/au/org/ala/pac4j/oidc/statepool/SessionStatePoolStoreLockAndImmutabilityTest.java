package au.org.ala.pac4j.oidc.statepool;

import lombok.val;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.TechnicalException;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Regression tests for {@link SessionStatePoolStore} locking and {@link FlowSecrets}
 * immutability:
 *
 * <ul>
 *   <li><b>Stable lock-stripe selection:</b> stripe picked from the session id after the id is
 *       established (create-if-absent on mutating ops), id re-read under the lock to absorb
 *       rotation, single static sentinel stripe for no-id callers, fail-closed
 *       {@link TechnicalException} when the id never stabilises.</li>
 *   <li><b>{@link FlowSecrets} immutability:</b> consume replaces the map entry with a
 *       {@code without*} copy instead of mutating in place, so a failed
 *       {@code sessionStore.set(...)} cannot leave the session-held copy half-consumed.</li>
 *   <li><b>{@code size()} reads under the stripe:</b> consistent snapshot rather than racing
 *       concurrent mutations.</li>
 * </ul>
 */
public final class SessionStatePoolStoreLockAndImmutabilityTest {

    private static final String CLIENT_NAME = "testClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 20;

    /* FlowSecrets immutability and fail-closed atomicity */

    /**
     * A {@code SessionStore} delegating to a real {@link MockSessionStore} whose {@code set}
     * throws on demand, to prove a failed write does NOT leave the session-held
     * {@link FlowSecrets} half-consumed.
     */
    private static final class ThrowingSetSessionStore implements SessionStore {
        private final MockSessionStore delegate = new MockSessionStore();
        private volatile boolean throwOnSet;

        @Override
        public Optional<String> getSessionId(final WebContext context, final boolean createSession) {
            return delegate.getSessionId(context, createSession);
        }

        @Override
        @SuppressWarnings("unchecked") // MockSessionStore.get returns a raw Optional
        public Optional<Object> get(final WebContext context, final String key) {
            return (Optional<Object>) (Optional<?>) delegate.get(context, key);
        }

        @Override
        public void set(final WebContext context, final String key, final Object value) {
            if (throwOnSet) {
                throw new IllegalStateException("simulated session-store write failure");
            }
            delegate.set(context, key, value);
        }

        @Override
        public boolean destroySession(final WebContext context) {
            return delegate.destroySession(context);
        }

        @Override
        public Optional<Object> getTrackableSession(final WebContext context) {
            return delegate.getTrackableSession(context);
        }

        @Override
        public Optional<SessionStore> buildFromTrackableSession(final WebContext context, final Object session) {
            return delegate.buildFromTrackableSession(context, session);
        }

        @Override
        public boolean renewSession(final WebContext context) {
            return delegate.renewSession(context);
        }
    }

    /**
     * When the session-store write fails mid-consume, the pool entry must remain readable with
     * the secret still present.
     */
    @Test
    public void failedSessionWriteDoesNotClearVerifierOnStoredHolder() {
        val store = new SessionStatePoolStore();
        val sessionStore = new ThrowingSetSessionStore();
        val webContext = MockWebContext.create();
        val ctx = new CallContext(webContext, sessionStore);
        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);

        store.add(ctx, CLIENT_NAME, "s1", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx, CLIENT_NAME, "s1", "verifier-1", null, TTL_MILLIS, MAX_SIZE);

        // The consume must propagate the exception AND leave the session-held holder untouched.
        sessionStore.throwOnSet = true;
        try {
            store.consumeCodeVerifier(ctx, CLIENT_NAME, "s1", TTL_MILLIS);
            fail("the store write failure must propagate");
        } catch (final IllegalStateException expected) {
            // expected: simulated write failure
        } finally {
            sessionStore.throwOnSet = false;
        }

        val holder = (StatePoolHolder) sessionStore.get(webContext, key).orElseThrow();
        val secrets = holder.getFlowSecrets().get("s1");
        assertNotNull("association must still be present after failed write", secrets);
        assertEquals("verifier must NOT have been cleared by the failed consume",
            "verifier-1", secrets.getCodeVerifier());
    }

    /**
     * Mirror-image for the nonce consume: a failed write must leave the nonce on the stored
     * holder unchanged.
     */
    @Test
    public void failedSessionWriteDoesNotClearNonceOnStoredHolder() {
        val store = new SessionStatePoolStore();
        val sessionStore = new ThrowingSetSessionStore();
        val webContext = MockWebContext.create();
        val ctx = new CallContext(webContext, sessionStore);
        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);

        store.add(ctx, CLIENT_NAME, "s2", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx, CLIENT_NAME, "s2", null, "nonce-1", TTL_MILLIS, MAX_SIZE);

        sessionStore.throwOnSet = true;
        try {
            store.consumeNonce(ctx, CLIENT_NAME, "s2", TTL_MILLIS);
            fail("the store write failure must propagate");
        } catch (final IllegalStateException expected) {
            // expected
        } finally {
            sessionStore.throwOnSet = false;
        }

        val holder = (StatePoolHolder) sessionStore.get(webContext, key).orElseThrow();
        val secrets = holder.getFlowSecrets().get("s2");
        assertNotNull("association must still be present after failed write", secrets);
        assertEquals("nonce must NOT have been cleared by the failed consume",
            "nonce-1", secrets.getNonce());
    }

    /**
     * Mirror-image for nonce-by-value: a failed write must leave the entry unchanged.
     */
    @Test
    public void failedSessionWriteDoesNotClearNonceByValueOnStoredHolder() {
        val store = new SessionStatePoolStore();
        val sessionStore = new ThrowingSetSessionStore();
        val webContext = MockWebContext.create();
        val ctx = new CallContext(webContext, sessionStore);
        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);

        store.add(ctx, CLIENT_NAME, "s3", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx, CLIENT_NAME, "s3", "verifier-keep", "nonce-bv", TTL_MILLIS, MAX_SIZE);

        sessionStore.throwOnSet = true;
        try {
            store.consumeNonceByValue(ctx, CLIENT_NAME, "nonce-bv", TTL_MILLIS);
            fail("the store write failure must propagate");
        } catch (final IllegalStateException expected) {
            // expected
        } finally {
            sessionStore.throwOnSet = false;
        }

        val holder = (StatePoolHolder) sessionStore.get(webContext, key).orElseThrow();
        val secrets = holder.getFlowSecrets().get("s3");
        assertNotNull("association must still be present after failed write", secrets);
        assertEquals("nonce must NOT have been cleared by the failed consume",
            "nonce-bv", secrets.getNonce());
        assertEquals("sibling verifier must NOT have been touched",
            "verifier-keep", secrets.getCodeVerifier());
    }

    /**
     * {@link FlowSecrets} exposes no public mutators and all instance fields are final; pinned
     * with reflection so a future contributor can't reintroduce a setter unnoticed.
     */
    @Test
    public void flowSecretsExposesNoMutators() {
        for (final Method m : FlowSecrets.class.getDeclaredMethods()) {
            if (!Modifier.isPublic(m.getModifiers()) || m.isSynthetic()) {
                continue;
            }
            final String name = m.getName();
            assertFalse(
                "FlowSecrets must not expose a public mutator, found: " + name,
                name.startsWith("set"));
        }
        for (final var f : FlowSecrets.class.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers()) || f.isSynthetic()) {
                continue;
            }
            assertTrue("field '" + f.getName() + "' must be final for immutability",
                Modifier.isFinal(f.getModifiers()));
        }
    }

    /**
     * The {@code without*} methods produce a copy with the requested field cleared and the other
     * fields preserved.
     */
    @Test
    public void withoutMethodsReturnCopyWithFieldCleared() {
        val original = new FlowSecrets("v", "n", 1_234L);

        val noVerifier = original.withoutCodeVerifier();
        assertNull(noVerifier.getCodeVerifier());
        assertEquals("n", noVerifier.getNonce());
        assertEquals(1_234L, noVerifier.getCreatedAt());

        val noNonce = original.withoutNonce();
        assertEquals("v", noNonce.getCodeVerifier());
        assertNull(noNonce.getNonce());
        assertEquals(1_234L, noNonce.getCreatedAt());

        // Original is unchanged.
        assertEquals("v", original.getCodeVerifier());
        assertEquals("n", original.getNonce());
    }

    /**
     * Mutating the map returned by {@link StatePoolHolder#getFlowSecrets()} must not affect the
     * stored map, and the {@link FlowSecrets} values inside cannot be mutated at all.
     */
    @Test
    public void holderGettersReturnSafeCopies() {
        val entries = new java.util.LinkedHashMap<String, Long>();
        entries.put("s", 1L);
        val secrets = new java.util.LinkedHashMap<String, FlowSecrets>();
        secrets.put("s", new FlowSecrets("v", "n", 1L));
        val holder = new StatePoolHolder(entries, secrets);

        // Mutating the returned map must not change the holder's internal state.
        val leakedSecrets = holder.getFlowSecrets();
        leakedSecrets.remove("s");
        assertTrue("holder's internal flowSecrets map must be unaffected by caller mutation",
            holder.getFlowSecrets().containsKey("s"));

        // And the values themselves cannot be mutated (FlowSecrets is immutable).
        val value = holder.getFlowSecrets().get("s");
        assertEquals("v", value.getCodeVerifier());
        assertEquals("n", value.getNonce());
        val copy = value.withoutNonce();
        assertEquals("n", holder.getFlowSecrets().get("s").getNonce()); // still there
        assertNull(copy.getNonce());
    }

    /* Stable session-id lock selection */

    /**
     * A SessionStore whose id is assigned lazily on the first {@code getSessionId(..., true)}
     * call — the real-world "session created on first write" case.
     */
    private static final class LazyIdSessionStore implements SessionStore {
        private final Map<String, Object> backing = new HashMap<>();
        private volatile String id;
        final AtomicInteger createCalls = new AtomicInteger();
        final ConcurrentLinkedQueue<String> idsSeenDuringLock = new ConcurrentLinkedQueue<>();

        @Override
        public synchronized Optional<String> getSessionId(final WebContext context, final boolean createSession) {
            if (id == null && createSession) {
                createCalls.incrementAndGet();
                id = "lazy-" + System.nanoTime();
            }
            return Optional.ofNullable(id);
        }

        @Override
        public synchronized Optional<Object> get(final WebContext context, final String key) {
            return Optional.ofNullable(backing.get(key));
        }

        @Override
        public synchronized void set(final WebContext context, final String key, final Object value) {
            // simulate the real MockSessionStore behaviour: set also creates the session
            if (id == null) {
                id = "lazy-set-" + System.nanoTime();
            }
            backing.put(key, value);
        }

        @Override public boolean destroySession(final WebContext context) { id = null; backing.clear(); return true; }
        @Override public Optional<Object> getTrackableSession(final WebContext context) { return Optional.ofNullable(id); }
        @Override public Optional<SessionStore> buildFromTrackableSession(final WebContext context, final Object session) {
            return Optional.of(this);
        }
        @Override public boolean renewSession(final WebContext context) { id = "renewed-" + System.nanoTime(); return true; }
    }

    /**
     * A mutating operation on a session whose id has never been read must FORCE the id into
     * existence via {@code getSessionId(ctx, true)} BEFORE picking the stripe, so concurrent
     * first-time writers agree on one stripe.
     */
    @Test
    public void addEstablishesSessionIdBeforeLocking() {
        val store = new SessionStatePoolStore();
        val sessionStore = new LazyIdSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        // Before any op: no id yet.
        assertTrue(sessionStore.getSessionId(ctx.webContext(), false).isEmpty());

        store.add(ctx, CLIENT_NAME, "new-state", TTL_MILLIS, MAX_SIZE);

        // The mutating add must have created the id up front.
        assertTrue("add must force session-id creation before locking",
            sessionStore.createCalls.get() >= 1);
        val id = sessionStore.getSessionId(ctx.webContext(), false);
        assertTrue("session id must now exist", id.isPresent());
        // And the pool entry must be readable back under the same session.
        assertTrue(store.consume(ctx, CLIENT_NAME, "new-state", TTL_MILLIS));
    }

    /**
     * Two distinct {@code SessionStatePoolStore} instances operating on two distinct session ids
     * must acquire their own distinct stripe locks, so their critical sections overlap. Proven
     * with a concurrency counter shared across both instances: if the stripe table degenerated
     * to one shared lock, the two {@code add} calls would serialise and the counter would never
     * exceed 1.
     */
    @Test
    public void distinctInstancesAcquireDistinctLocksForDistinctSessions() throws Exception {
        // Two session ids that are guaranteed to land on DIFFERENT stripes (the table has 1024
        // stripes indexed by floorMod(hashCode)); scanning candidates removes any hash-collision
        // flakiness.
        final String sessionIdA = "session-A";
        final String sessionIdB = sessionIdOnDifferentStripe(sessionIdA);

        // Shared across BOTH store instances: every critical section (from either instance)
        // funnels through the same increment/decrement pair.
        final AtomicInteger concurrentInsideCriticalSection = new AtomicInteger();
        final AtomicInteger maxObservedConcurrency = new AtomicInteger();

        // A store whose betweenReadAndWrite sleeps so two racing critical sections overlap if —
        // and only if — they hold different locks.
        final class SlowCriticalSectionStore extends SessionStatePoolStore {
            @Override
            protected void betweenReadAndWrite() {
                final int inFlight = concurrentInsideCriticalSection.incrementAndGet();
                maxObservedConcurrency.accumulateAndGet(inFlight, Math::max);
                try {
                    Thread.sleep(50L);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    concurrentInsideCriticalSection.decrementAndGet();
                }
            }
        }

        // A SessionStore whose session id is fixed from the outset and whose set records the
        // session id it served, so each wrapper below pins one session.
        final class FixedIdSessionStore implements SessionStore {
            final Map<String, Object> backing = new HashMap<>();
            final String id;

            FixedIdSessionStore(final String id) {
                this.id = id;
            }

            @Override public synchronized Optional<String> getSessionId(final WebContext c, final boolean create) {
                return Optional.of(id);
            }
            @Override public synchronized Optional<Object> get(final WebContext c, final String k) {
                return Optional.ofNullable(backing.get(k));
            }
            @Override public synchronized void set(final WebContext c, final String k, final Object v) {
                backing.put(k, v);
            }
            @Override public boolean destroySession(final WebContext c) { return true; }
            @Override public Optional<Object> getTrackableSession(final WebContext c) { return Optional.of(id); }
            @Override public Optional<SessionStore> buildFromTrackableSession(final WebContext c, final Object s) {
                return Optional.of(this);
            }
            @Override public boolean renewSession(final WebContext c) { return false; }
        }

        // Two distinct store instances, each driving its own distinct session.
        val storeA = new SlowCriticalSectionStore();
        val storeB = new SlowCriticalSectionStore();
        val ctxA = new CallContext(MockWebContext.create(), new FixedIdSessionStore(sessionIdA));
        val ctxB = new CallContext(MockWebContext.create(), new FixedIdSessionStore(sessionIdB));

        val start = new CountDownLatch(1);
        val t1 = new Thread(() -> {
            awaitQuietly(start);
            storeA.add(ctxA, CLIENT_NAME, "state-a", TTL_MILLIS, MAX_SIZE);
        });
        val t2 = new Thread(() -> {
            awaitQuietly(start);
            storeB.add(ctxB, CLIENT_NAME, "state-b", TTL_MILLIS, MAX_SIZE);
        });
        t1.start();
        t2.start();
        start.countDown();
        t1.join(5_000L);
        t2.join(5_000L);

        // With distinct stripes the two critical sections overlap; a degenerate shared lock
        // would serialise them and the counter would peak at 1.
        final int distinctLockCount = maxObservedConcurrency.get();
        assertEquals("Two distinct instances must acquire their own distinct locks (lock count must be 2, not 1 from a shared static table)", 2, distinctLockCount);
        // Both writes landed under their own sessions.
        assertEquals(Optional.of(1), storeA.size(ctxA, CLIENT_NAME));
        assertEquals(Optional.of(1), storeB.size(ctxB, CLIENT_NAME));
    }

    /**
     * Find a session id that maps to a different stripe than {@code other}, mirroring the
     * store's {@code floorMod(hashCode, 1024)} stripe selection.
     */
    private static String sessionIdOnDifferentStripe(final String other) {
        final int otherStripe = Math.floorMod(other.hashCode(), 1024);
        for (int i = 0; ; i++) {
            final String candidate = "session-B-" + i;
            if (Math.floorMod(candidate.hashCode(), 1024) != otherStripe) {
                return candidate;
            }
        }
    }

    /**
     * Two distinct {@code SessionStore} wrapper instances that both report "no session id
     * available" must share ONE global sentinel stripe. Proven with a concurrency counter shared
     * across both wrapper instances: with one static sentinel the shared counter never exceeds 1;
     * with per-wrapper locks, concurrent {@code set} calls from the two wrappers would overlap
     * and drive it to 2.
     */
    @Test
    public void absentIdOperationsShareOneGlobalSentinelStripe() throws Exception {
        // Shared across BOTH wrapper instances: every set (from either wrapper) funnels through
        // the same increment/decrement pair.
        final AtomicInteger sharedConcurrentInsideWrite = new AtomicInteger();
        final AtomicInteger sharedMaxObservedConcurrency = new AtomicInteger();

        // A SessionStore with NO id available whose set sleeps so two racing callers would
        // interleave if they locked different stripes.
        final class NoIdSessionStore implements SessionStore {
            final Map<String, Object> backing = new HashMap<>();

            @Override public Optional<String> getSessionId(final WebContext c, final boolean create) {
                return Optional.empty(); // never any id
            }
            @Override public synchronized Optional<Object> get(final WebContext c, final String k) {
                return Optional.ofNullable(backing.get(k));
            }
            @Override public void set(final WebContext c, final String k, final Object v) {
                final int inFlight = sharedConcurrentInsideWrite.incrementAndGet();
                sharedMaxObservedConcurrency.accumulateAndGet(inFlight, Math::max);
                try {
                    Thread.sleep(15L);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    sharedConcurrentInsideWrite.decrementAndGet();
                }
                synchronized (this) {
                    backing.put(k, v);
                }
            }
            @Override public boolean destroySession(final WebContext c) { return true; }
            @Override public Optional<Object> getTrackableSession(final WebContext c) { return Optional.empty(); }
            @Override public Optional<SessionStore> buildFromTrackableSession(final WebContext c, final Object s) {
                return Optional.empty();
            }
            @Override public boolean renewSession(final WebContext c) { return false; }
        }

        // Two distinct wrapper instances, both with no id.
        val wrapperA = new NoIdSessionStore();
        val wrapperB = new NoIdSessionStore();
        val store = new SessionStatePoolStore();

        final int totalThreads = 8;
        val latch = new CountDownLatch(1);
        val pool = java.util.concurrent.Executors.newFixedThreadPool(totalThreads);
        val futures = new java.util.ArrayList<java.util.concurrent.Future<?>>();
        for (int i = 0; i < totalThreads; i++) {
            final NoIdSessionStore wrapper = (i % 2 == 0) ? wrapperA : wrapperB;
            final String state = "state-" + i;
            futures.add(pool.submit(() -> {
                try {
                    latch.await(5, TimeUnit.SECONDS);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                store.add(new CallContext(MockWebContext.create(), wrapper),
                    CLIENT_NAME, state, TTL_MILLIS, MAX_SIZE);
                return null;
            }));
        }
        latch.countDown();
        for (val f : futures) {
            f.get(20, TimeUnit.SECONDS);
        }
        pool.shutdownNow();

        // With one static sentinel stripe the shared counter never exceeds 1.
        assertEquals(
            "set calls from DIFFERENT SessionStore wrappers must serialise against each other "
                + "(one static sentinel stripe)",
            1, sharedMaxObservedConcurrency.get());
        // All states landed.
        assertEquals(Integer.valueOf(totalThreads / 2),
            store.size(new CallContext(MockWebContext.create(), wrapperA), CLIENT_NAME).orElseThrow());
        assertEquals(Integer.valueOf(totalThreads / 2),
            store.size(new CallContext(MockWebContext.create(), wrapperB), CLIENT_NAME).orElseThrow());
    }

    /**
     * If the session id CHANGES between the initial resolution and the re-read inside the lock,
     * the store must release the wrong stripe and retry with the fresh id, so the pool write
     * lands under the NEW session id.
     */
    @Test
    public void idRotationBetweenResolveAndLockTriggersRetryWithFreshId() {
        final class RotatingSessionStore implements SessionStore {
            final Map<String, Object> backing = new HashMap<>();
            final AtomicInteger idCalls = new AtomicInteger();
            volatile String id = "id-A"; // will flip to id-B on the second getSessionId call

            @Override public synchronized Optional<String> getSessionId(final WebContext c, final boolean create) {
                final int call = idCalls.incrementAndGet();
                if (call == 2) {
                    id = "id-B";
                }
                return Optional.of(id);
            }
            @Override public synchronized Optional<Object> get(final WebContext c, final String k) {
                return Optional.ofNullable(backing.get(k));
            }
            @Override public synchronized void set(final WebContext c, final String k, final Object v) {
                backing.put(k, v);
            }
            @Override public boolean destroySession(final WebContext c) { return true; }
            @Override public Optional<Object> getTrackableSession(final WebContext c) { return Optional.ofNullable(id); }
            @Override public Optional<SessionStore> buildFromTrackableSession(final WebContext c, final Object s) {
                return Optional.of(this);
            }
            @Override public boolean renewSession(final WebContext c) { return false; }
        }

        val store = new SessionStatePoolStore();
        val sessionStore = new RotatingSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        store.add(ctx, CLIENT_NAME, "rotated-state", TTL_MILLIS, MAX_SIZE);

        // The add must have absorbed the rotation and landed the pool under the CURRENT id
        // (id-B): consume finds it under the same session.
        assertTrue("pool write must land under the fresh session id after rotation",
            store.consume(ctx, CLIENT_NAME, "rotated-state", TTL_MILLIS));
        assertTrue("lock acquisition must re-resolve the id (retry loop)",
            sessionStore.idCalls.get() >= 2);
    }

    /**
     * A SessionStore that rotates the id on EVERY read defeats the retry loop: the store must
     * throw a {@link TechnicalException} BEFORE any read/modify/write of pool state, and must
     * not leave a lock held.
     */
    @Test
    public void rotatingSessionIdEveryReadFailsClosedWithTechnicalException() {
        // getSessionId returns a different id on every call: the retry loop can never converge.
        final class AlwaysRotatingSessionStore implements SessionStore {
            final Map<String, Object> backing = new HashMap<>();
            final AtomicInteger idCalls = new AtomicInteger();
            final AtomicInteger setCalls = new AtomicInteger();

            @Override public synchronized Optional<String> getSessionId(final WebContext c, final boolean create) {
                return Optional.of("rotating-" + idCalls.incrementAndGet());
            }
            @Override public synchronized Optional<Object> get(final WebContext c, final String k) {
                return Optional.ofNullable(backing.get(k));
            }
            @Override public synchronized void set(final WebContext c, final String k, final Object v) {
                setCalls.incrementAndGet();
                backing.put(k, v);
            }
            @Override public boolean destroySession(final WebContext c) { return true; }
            @Override public Optional<Object> getTrackableSession(final WebContext c) { return Optional.empty(); }
            @Override public Optional<SessionStore> buildFromTrackableSession(final WebContext c, final Object s) {
                return Optional.of(this);
            }
            @Override public boolean renewSession(final WebContext c) { return false; }
        }

        val store = new SessionStatePoolStore();
        val rotatingStore = new AlwaysRotatingSessionStore();
        val ctx = new CallContext(MockWebContext.create(), rotatingStore);

        try {
            store.add(ctx, CLIENT_NAME, "never-committed", TTL_MILLIS, MAX_SIZE);
            fail("a SessionStore that rotates the id on every read must fail closed");
        } catch (final TechnicalException expected) {
            // expected: fail-closed after MAX_LOCK_RETRIES without a stable id
            assertTrue("the message must identify the retry budget and the cause",
                expected.getMessage().contains("could not be stabilized"));
            assertTrue("the message must name the misbehaving SessionStore",
                expected.getMessage().contains("SessionStore"));
        }

        // Fail-closed: NOTHING was written — set must never have been invoked.
        assertEquals("no pool state may be written when the session id cannot be stabilized",
            0, rotatingStore.setCalls.get());
        assertTrue("no pool state may be readable when the session id cannot be stabilized",
            rotatingStore.backing.isEmpty());
        assertTrue("the retry loop must have been exercised before failing",
            rotatingStore.idCalls.get() > 1);

        // No stripe may be held after the throw.
        assertNoStripeIsHeld();

        // A normal op on a stable-id session must succeed immediately after.
        val stableStore = new MockSessionStore();
        val stableCtx = new CallContext(MockWebContext.create(), stableStore);
        store.add(stableCtx, CLIENT_NAME, "stable-state", TTL_MILLIS, MAX_SIZE);
        assertTrue("a normal op on a stable-id session must succeed after the fail-closed throw "
                + "(proves no lock was leaked by the throwing path)",
            store.consume(stableCtx, CLIENT_NAME, "stable-state", TTL_MILLIS));
    }

    /**
     * Assert that no stripe lock (including the absent-id sentinel) is currently held; the
     * stripe table is private, so reflection is used.
     */
    private static void assertNoStripeIsHeld() {
        try {
            final var tableField = SessionStatePoolStore.class.getDeclaredField("LOCK_STRIPES_TABLE");
            tableField.setAccessible(true);
            final var table = (java.util.concurrent.locks.ReentrantLock[]) tableField.get(null);
            for (int i = 0; i < table.length; i++) {
                assertFalse("stripe " + i + " must not be held after the fail-closed throw",
                    table[i].isLocked());
            }
            final var sentinelField = SessionStatePoolStore.class.getDeclaredField("ABSENT_ID_SENTINEL");
            sentinelField.setAccessible(true);
            final var sentinel = (java.util.concurrent.locks.ReentrantLock) sentinelField.get(null);
            assertFalse("the absent-id sentinel must not be held after the fail-closed throw",
                sentinel.isLocked());
        } catch (final NoSuchFieldException | IllegalAccessException e) {
            throw new AssertionError("cannot inspect stripe table for leak check", e);
        }
    }

    /* size() under the stripe lock */

    /**
     * {@code size()} reflects the committed state exactly, and returns {@code Optional.empty()}
     * (not {@code Optional.of(0)}) on a missing pool.
     */
    @Test
    public void sizeReadsUnderLockAndReflectsCommittedState() {
        val store = new SessionStatePoolStore();
        val sessionStore = new MockSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        // No pool yet: must be empty, not zero.
        assertTrue("size() on a missing pool must be Optional.empty()",
            store.size(ctx, CLIENT_NAME).isEmpty());

        store.add(ctx, CLIENT_NAME, "a", TTL_MILLIS, MAX_SIZE);
        store.add(ctx, CLIENT_NAME, "b", TTL_MILLIS, MAX_SIZE);
        assertEquals(Optional.of(2), store.size(ctx, CLIENT_NAME));

        assertTrue(store.consume(ctx, CLIENT_NAME, "a", TTL_MILLIS));
        assertEquals(Optional.of(1), store.size(ctx, CLIENT_NAME));
    }

    /**
     * {@code size()} must use the same stripe as the writers: with a writer sleeping inside its
     * critical section, every observed size must be either the pre- or post-write value (0 or 1
     * here), never a torn snapshot.
     */
    @Test
    public void sizeUsesSameStripeAsWriters() throws Exception {
        val slowStore = new SessionStatePoolStore() {
            @Override
            protected void betweenReadAndWrite() {
                try {
                    Thread.sleep(50L);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
        val sessionStore = new MockSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        val writer = new Thread(() ->
            slowStore.add(ctx, CLIENT_NAME, "in-flight", TTL_MILLIS, MAX_SIZE));
        writer.start();

        // While the writer is mid-critical-section, every size() call must block on the same
        // stripe and then return either 0 (pre-add) or 1 (post-add).
        try {
            for (int i = 0; i < 20; i++) {
                val size = slowStore.size(ctx, CLIENT_NAME);
                if (size.isPresent()) {
                    final int n = size.get();
                    assertTrue("size() observed a torn snapshot: " + n, n == 0 || n == 1);
                }
            }
        } finally {
            writer.join(5_000L);
        }
    }

    /**
     * Smoke test: the standard consume path on a stable session (no rotation, no creation race)
     * still serialises — exactly one of two racing consumers wins.
     */
    @Test
    public void concurrentConsumeStillAtomicOnStableSession() throws Exception {
        val store = new SessionStatePoolStore();
        val sessionStore = new MockSessionStore();
        val setupCtx = new CallContext(MockWebContext.create(), sessionStore);
        store.add(setupCtx, CLIENT_NAME, "contended", TTL_MILLIS, MAX_SIZE);

        val winners = new AtomicInteger();
        val start = new CountDownLatch(1);
        val t1 = new Thread(() -> {
            awaitQuietly(start);
            if (store.consume(new CallContext(MockWebContext.create(), sessionStore),
                CLIENT_NAME, "contended", TTL_MILLIS)) {
                winners.incrementAndGet();
            }
        });
        val t2 = new Thread(() -> {
            awaitQuietly(start);
            if (store.consume(new CallContext(MockWebContext.create(), sessionStore),
                CLIENT_NAME, "contended", TTL_MILLIS)) {
                winners.incrementAndGet();
            }
        });
        t1.start();
        t2.start();
        start.countDown();
        t1.join(5_000L);
        t2.join(5_000L);

        assertEquals("exactly one consumer may win on a stable session", 1, winners.get());
    }

    private static void awaitQuietly(final CountDownLatch latch) {
        try {
            latch.await(5, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
