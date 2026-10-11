package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import lombok.val;
import org.junit.Before;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;

import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for PKCE {@code code_verifier} pooling (on by default): the verifier is associated with
 * its flow's {@code state} on the redirect, and on the callback the retriever recovers the
 * verifier matching the echoed state. Covers concurrent flows, one-time use, the
 * {@code withState=false} raw-session fallback, serialization round-trip, TTL/LRU on
 * associations, and the {@code pkcePoolingEnabled=false} kill-switch.
 */
public final class PkcePoolingTest {

    private static final String CLIENT_NAME = "testClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 20;

    private StatePool statePool;
    private StatePoolValueRetriever retriever;
    private MockSessionStore sessionStore;
    private OidcClient client;

    @Before
    public void setUp() {
        statePool = new StatePool(new SessionStatePoolStore(), TTL_MILLIS, MAX_SIZE);
        retriever = new StatePoolValueRetriever(statePool); // PKCE pooling ON by default
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

    /** Redirect side for one flow: pool the state and associate its verifier. */
    private void redirectFlow(final String stateValue, final String verifierValue) {
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        statePool.add(ctx, CLIENT_NAME, stateValue);
        statePool.addFlowSecrets(ctx, CLIENT_NAME, stateValue, verifierValue, null);
    }

    /**
     * Concurrent flows: the callback for flow 1 supplies its state and the retriever returns
     * flow 1's verifier; flow 2's entry is left untouched.
     */
    @Test
    public void concurrentFlowsEachRecoverTheirOwnVerifier() {
        redirectFlow("state-1", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0001");
        redirectFlow("state-2", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0002");

        val result1 = retriever.retrieve(contextWithResponseState("state-1"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("flow 1's verifier must be returned", result1.isPresent());
        assertTrue("must be a CodeVerifier", result1.get() instanceof CodeVerifier);
        assertEquals("must be flow 1's verifier, not flow 2's",
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0001"), result1.get());

        val result2 = retriever.retrieve(contextWithResponseState("state-2"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("flow 2's verifier must still be present", result2.isPresent());
        assertEquals(new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-0002"), result2.get());
    }

    /**
     * One-time use, fail closed: a second retrieval for the same state returns empty and must
     * NOT serve the shared single session slot (here deliberately populated with a later flow's
     * verifier to prove it is not served).
     */
    @Test
    public void verifierIsOneTimeUseThenFailsClosed() {
        redirectFlow("state-x", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-pooled");
        // Stock pac4j leaves the most recent verifier in the single slot (additive design).
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-latest"));

        val first = retriever.retrieve(contextWithResponseState("state-x"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue(first.isPresent());
        assertEquals("first retrieval returns the pooled verifier",
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-pooled"), first.get());

        val second = retriever.retrieve(contextWithResponseState("state-x"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("second retrieval must fail closed, not serve the cross-flow slot value",
            second.isEmpty());
    }

    /**
     * A request with no {@code state} parameter ({@code withState=false}) uses the raw session
     * fallback and returns the slot value.
     */
    @Test
    public void requestWithoutStateParamUsesRawSessionFallback() {
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-slot"));

        val result = retriever.retrieve(contextWithResponseState(null),
            client.getCodeVerifierSessionAttributeName(), client);

        assertTrue("no state param → raw session fallback must return the slot value",
            result.isPresent());
        assertEquals(new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-slot"), result.get());
    }

    /**
     * A verifier pooled before serialization is still returned, correctly, after the holder is
     * deserialized.
     */
    @Test
    public void associationMapSurvivesSerializationRoundTrip() throws Exception {
        redirectFlow("state-rt", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-roundtrip");

        // Round-trip the holder in the session through Java serialization.
        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);
        val original = (StatePoolHolder) sessionStore.get(
            new CallContext(MockWebContext.create(), sessionStore).webContext(), key).orElseThrow();
        val bytes = new java.io.ByteArrayOutputStream();
        try (val out = new java.io.ObjectOutputStream(bytes)) {
            out.writeObject(original);
        }
        final StatePoolHolder restored;
        try (val in = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(bytes.toByteArray()))) {
            restored = (StatePoolHolder) in.readObject();
        }
        sessionStore.set(new CallContext(MockWebContext.create(), sessionStore).webContext(), key, restored);

        val result = retriever.retrieve(contextWithResponseState("state-rt"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("pooled verifier must survive serialization", result.isPresent());
        assertEquals(new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-roundtrip"), result.get());
    }

    /**
     * TTL applies to association entries: an association older than the TTL is swept and its
     * verifier is no longer served.
     */
    @Test
    public void expiredAssociationIsSwept() throws InterruptedException {
        val shortPool = new StatePool(new SessionStatePoolStore(), 50L, MAX_SIZE);
        val shortRetriever = new StatePoolValueRetriever(shortPool);
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        shortPool.add(ctx, CLIENT_NAME, "state-exp");
        shortPool.addFlowSecrets(ctx, CLIENT_NAME, "state-exp", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-expired", null);

        Thread.sleep(90L);

        val result = shortRetriever.retrieve(contextWithResponseState("state-exp"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("expired association must not serve a verifier", result.isEmpty());
    }

    /** LRU eviction covers the association map: associations die with their state. */
    @Test
    public void lruEvictionCoversAssociations() {
        val tinyPool = new StatePool(new SessionStatePoolStore(), TTL_MILLIS, 2);
        val tinyRetriever = new StatePoolValueRetriever(tinyPool);
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        tinyPool.add(ctx, CLIENT_NAME, "s1");
        tinyPool.addFlowSecrets(ctx, CLIENT_NAME, "s1", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk--v1", null);
        tinyPool.add(ctx, CLIENT_NAME, "s2");
        tinyPool.addFlowSecrets(ctx, CLIENT_NAME, "s2", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk--v2", null);
        // Overflow beyond maxSize=2 with a third flow.
        tinyPool.add(ctx, CLIENT_NAME, "s3");
        tinyPool.addFlowSecrets(ctx, CLIENT_NAME, "s3", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk--v3", null);

        // s1 is the eldest: its state AND its association are evicted.
        assertTrue(tinyRetriever.retrieve(contextWithResponseState("s1"),
            client.getCodeVerifierSessionAttributeName(), client).isEmpty());
        val s3 = tinyRetriever.retrieve(contextWithResponseState("s3"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue(s3.isPresent());
        assertEquals(new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk--v3"), s3.get());
    }

    /**
     * With {@code pkcePoolingEnabled=false} the verifier branch is skipped and the raw session
     * fallback is always used, even when a pooled association exists (and is left unconsumed).
     */
    @Test
    public void pkcePoolingDisabledAlwaysUsesSessionFallback() {
        val offRetriever = new StatePoolValueRetriever(statePool, null, false);
        redirectFlow("state-off", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-pooledoff");
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-slotoff"));

        val result = offRetriever.retrieve(contextWithResponseState("state-off"),
            client.getCodeVerifierSessionAttributeName(), client);

        assertTrue(result.isPresent());
        assertEquals("pooling off → session slot served, not the pooled verifier",
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-slotoff"), result.get());
        // The pooled association was NOT consumed: a pooling-ON retriever still finds it.
        val onResult = retriever.retrieve(contextWithResponseState("state-off"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("association must be untouched when pooling is off", onResult.isPresent());
        assertEquals(new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-pooledoff"), onResult.get());
    }

    /**
     * An unknown echoed state fails closed rather than serving the session slot: a state is
     * present on the request, so the pooled path owns the correlation.
     */
    @Test
    public void unknownStateWithStateParamFailsClosed() {
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-slotfb"));

        val result = retriever.retrieve(contextWithResponseState("no-such-state"),
            client.getCodeVerifierSessionAttributeName(), client);

        assertTrue("unknown state + state param present must fail closed (no slot fallback)",
            result.isEmpty());
    }

    /**
     * {@link StatePoolOidcClient#setPkcePoolingEnabled(boolean)} defaults to ON and is
     * toggleable.
     */
    @Test
    public void clientFlagDefaultsOnAndIsToggleable() {
        val configuration = new OidcConfiguration();
        configuration.setClientId("clientId");
        val poolClient = new StatePoolOidcClient(configuration);
        assertTrue("PKCE pooling must default to ON", poolClient.isPkcePoolingEnabled());
        poolClient.setPkcePoolingEnabled(false);
        assertFalse(poolClient.isPkcePoolingEnabled());
    }
}
