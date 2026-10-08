package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import lombok.val;
import org.junit.Before;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link StatePoolValueRetriever}, {@link StatePool} and {@link SessionStatePoolStore}:
 * a pooled state validates, an absent state does not, a consumed state cannot be reused,
 * TTL/LRU semantics hold, the pool is namespaced per client, and concurrent consumers cannot
 * double-spend the same state.
 */
public final class StatePoolValueRetrieverTest {

    private static final String CLIENT_NAME = "testClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 5;

    private StatePool statePool;
    private StatePoolValueRetriever retriever;
    private MockSessionStore sessionStore;
    private OidcClient client;

    @Before
    public void setUp() {
        statePool = new StatePool(new SessionStatePoolStore(), TTL_MILLIS, MAX_SIZE);
        retriever = new StatePoolValueRetriever(statePool);
        sessionStore = new MockSessionStore();
        val configuration = new OidcConfiguration();
        configuration.setClientId("clientId");
        client = new OidcClient(configuration);
        client.setName(CLIENT_NAME);
    }

    private CallContext contextWithResponseState(final String responseState) {
        val webContext = MockWebContext.create();
        if (responseState != null) {
            webContext.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, responseState);
        }
        return new CallContext(webContext, sessionStore);
    }

    @Test
    public void statePresentInPoolValidates() {
        statePool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "state-abc");

        val result = retriever.retrieve(contextWithResponseState("state-abc"),
            client.getStateSessionAttributeName(), client);

        assertTrue(result.isPresent());
        assertEquals(new State("state-abc"), result.get());
    }

    @Test
    public void absentStateDoesNotValidate() {
        val result = retriever.retrieve(contextWithResponseState("never-registered"),
            client.getStateSessionAttributeName(), client);

        assertTrue(result.isEmpty());
    }

    @Test
    public void usedStateCannotBeReused() {
        statePool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "one-time");

        val first = retriever.retrieve(contextWithResponseState("one-time"),
            client.getStateSessionAttributeName(), client);
        assertTrue(first.isPresent());

        val second = retriever.retrieve(contextWithResponseState("one-time"),
            client.getStateSessionAttributeName(), client);
        assertTrue(second.isEmpty());
    }

    @Test
    public void missingResponseStateParameterYieldsEmpty() {
        statePool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "some-state");

        val result = retriever.retrieve(contextWithResponseState(null),
            client.getStateSessionAttributeName(), client);

        assertTrue(result.isEmpty());
    }

    @Test
    public void expiredStateIsRejected() throws InterruptedException {
        val shortLivedPool = new StatePool(new SessionStatePoolStore(), 50L, MAX_SIZE);
        val shortLivedRetriever = new StatePoolValueRetriever(shortLivedPool);
        shortLivedPool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "expiring");

        Thread.sleep(90L);

        val result = shortLivedRetriever.retrieve(contextWithResponseState("expiring"),
            client.getStateSessionAttributeName(), client);
        assertTrue(result.isEmpty());
    }

    @Test
    public void poolEvictsLeastRecentlyUsedBeyondMaxSize() {
        val tinyPool = new StatePool(new SessionStatePoolStore(), TTL_MILLIS, 2);
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        tinyPool.add(ctx, CLIENT_NAME, "s1");
        tinyPool.add(ctx, CLIENT_NAME, "s2");
        tinyPool.add(ctx, CLIENT_NAME, "s3");

        assertEquals(Optional.of(2), tinyPool.size(ctx, CLIENT_NAME));
        assertFalse(tinyPool.consume(ctx, CLIENT_NAME, "s1"));
        assertTrue(tinyPool.consume(ctx, CLIENT_NAME, "s3"));
    }

    @Test
    public void poolIsScopedPerClientName() {
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        statePool.add(ctx, "otherClient", "foreign-state");

        // A state pooled under a different client name must not validate for this client.
        val result = retriever.retrieve(contextWithResponseState("foreign-state"),
            client.getStateSessionAttributeName(), client);
        assertTrue(result.isEmpty());
    }

    @Test
    public void stateFromFormPostBodyIsConsumed() {
        // MockWebContext surfaces posted form fields via getRequestParameter exactly like query
        // params, so this covers the form_post response mode identically.
        statePool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "form-post-state");

        val result = retriever.retrieve(contextWithResponseState("form-post-state"),
            client.getStateSessionAttributeName(), client);

        assertTrue(result.isPresent());
        assertEquals(new State("form-post-state"), result.get());
        // really consumed (one-time use)
        assertTrue(retriever.retrieve(contextWithResponseState("form-post-state"),
            client.getStateSessionAttributeName(), client).isEmpty());
    }

    /* concurrency */

    /**
     * A store that sleeps inside its critical section, widening the read-modify-write window so
     * a broken lock is deterministically detectable.
     */
    private static SessionStatePoolStore slowStore() {
        return new SessionStatePoolStore() {
            @Override
            protected void betweenReadAndWrite() {
                try {
                    Thread.sleep(20L);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        };
    }

    /**
     * Run {@code racers} against a {@code CyclicBarrier} so every thread is released at the same
     * instant. Returns the number of winners.
     */
    private static int raceToConsume(final List<StatePoolValueRetriever> retrievers,
                                     final String stateValue,
                                     final MockSessionStore sessionStore,
                                     final OidcClient client,
                                     final int totalThreads) throws Exception {
        final ExecutorService pool = Executors.newFixedThreadPool(totalThreads);
        final CyclicBarrier barrier = new CyclicBarrier(totalThreads);
        final AtomicInteger successes = new AtomicInteger();
        final List<Future<?>> futures = new ArrayList<>();

        for (int i = 0; i < totalThreads; i++) {
            final StatePoolValueRetriever r = retrievers.get(i % retrievers.size());
            futures.add(pool.submit(() -> {
                barrier.await(); // all threads released together
                val webContext = MockWebContext.create();
                webContext.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, stateValue);
                val ctx = new CallContext(webContext, sessionStore); // SAME session store => same session
                if (r.retrieve(ctx, client.getStateSessionAttributeName(), client).isPresent()) {
                    successes.incrementAndGet();
                }
                return null;
            }));
        }
        for (final Future<?> f : futures) {
            f.get(20, TimeUnit.SECONDS);
        }
        pool.shutdownNow();
        return successes.get();
    }

    /**
     * Many threads racing to consume the SAME state from the SAME session through a SINGLE store
     * instance must see exactly one success.
     */
    @Test
    public void concurrentConsumeOfSameStateDoesNotDoubleSpend() throws Exception {
        final StatePool racedPool = new StatePool(slowStore(), TTL_MILLIS, MAX_SIZE);
        final StatePoolValueRetriever racedRetriever = new StatePoolValueRetriever(racedPool);
        racedPool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "raced-state");

        final int winners = raceToConsume(List.of(racedRetriever), "raced-state", sessionStore, client, 32);

        assertEquals("exactly one consumer may win a given state", 1, winners);
        // the state is gone for everyone afterwards
        assertTrue(racedRetriever.retrieve(contextWithResponseState("raced-state"),
            client.getStateSessionAttributeName(), client).isEmpty());
    }

    /**
     * The consume lock is keyed by the SESSION ID in a static table, NOT by any store/pool
     * instance: two SEPARATE {@link SessionStatePoolStore} objects serving the SAME session must
     * still mutually exclude each other.
     */
    @Test
    public void consumeIsAtomicAcrossSeparateStoreInstancesSharingASession() throws Exception {
        final StatePoolValueRetriever retrieverA =
            new StatePoolValueRetriever(new StatePool(slowStore(), TTL_MILLIS, MAX_SIZE));
        final StatePoolValueRetriever retrieverB =
            new StatePoolValueRetriever(new StatePool(slowStore(), TTL_MILLIS, MAX_SIZE));

        // register the state through instance A's pool
        new StatePool(slowStore(), TTL_MILLIS, MAX_SIZE)
            .add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "shared-race");

        final int winners = raceToConsume(List.of(retrieverA, retrieverB), "shared-race", sessionStore, client, 32);

        assertEquals("across two store instances sharing a session, exactly one may win", 1, winners);
    }

    /* PKCE dispatch */

    /**
     * On a STATELESS request (no {@code state} parameter — the {@code withState=false} path)
     * the retriever must return the raw session value intact: a {@code CodeVerifier}, not a
     * {@link State}, and not empty.
     */
    @Test
    public void pkceCodeVerifierIsReturnedIntactViaFallback() {
        val verifier = new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(), verifier);

        // No `state` request param: the genuinely stateless case the raw-slot fallback exists for.
        val result = retriever.retrieve(contextWithResponseState(null),
            client.getCodeVerifierSessionAttributeName(), client);

        assertTrue("verifier must be returned", result.isPresent());
        assertTrue("must be a CodeVerifier, not a State",
            result.get() instanceof CodeVerifier);
        assertEquals("verifier must be returned intact, unmodified", verifier, result.get());
    }

    /**
     * The stateless fallback is a pure read: not consumed, not one-time use.
     */
    @Test
    public void pkceCodeVerifierIsNotConsumedByRetrieval() {
        val verifier = new CodeVerifier();
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(), verifier);

        val first = retriever.retrieve(contextWithResponseState(null),
            client.getCodeVerifierSessionAttributeName(), client);
        val second = retriever.retrieve(contextWithResponseState(null),
            client.getCodeVerifierSessionAttributeName(), client);

        assertTrue(first.isPresent());
        assertTrue("a non-state key must never be consumed / one-time-use", second.isPresent());
        assertEquals(verifier, second.get());
    }

    /**
     * A verifier retrieval that fails closed (state present, but no pooled association for it)
     * must leave the pooled STATE intact and un-consumed, so the state still validates
     * afterwards.
     */
    @Test
    public void pkceRetrievalLeavesPooledStateIntact() {
        statePool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "pkce-state");

        val verifierResult = retriever.retrieve(contextWithResponseState("pkce-state"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("state present + no association must fail closed", verifierResult.isEmpty());

        val stateResult = retriever.retrieve(contextWithResponseState("pkce-state"),
            client.getStateSessionAttributeName(), client);
        assertTrue("a failed-closed verifier lookup must not consume the pooled state",
            stateResult.isPresent());
        assertEquals(new State("pkce-state"), stateResult.get());
    }

    /**
     * The {@code state} key still goes through the pool: a state present only in the pool (not
     * in the single session slot) validates via the state key.
     */
    @Test
    public void stateKeyStillGoesThroughThePool() {
        // register in the pool only; deliberately do NOT write the single session slot
        statePool.add(new CallContext(MockWebContext.create(), sessionStore), CLIENT_NAME, "pooled-only");

        val result = retriever.retrieve(contextWithResponseState("pooled-only"),
            client.getStateSessionAttributeName(), client);

        assertTrue("state key must validate against the pool", result.isPresent());
        assertEquals(new State("pooled-only"), result.get());
        // consumed (one-time use)
        assertTrue(retriever.retrieve(contextWithResponseState("pooled-only"),
            client.getStateSessionAttributeName(), client).isEmpty());
    }
}
