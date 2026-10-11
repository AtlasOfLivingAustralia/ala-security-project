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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Integration-order tests modelling pac4j's real callback pipeline per callback:
 * {@code OidcCredentialsExtractor} consumes the state first, then {@code OidcAuthenticator}
 * retrieves the PKCE code_verifier, then {@code OidcProfileCreator} validates the nonce.
 *
 * <p>Pins the lifecycle decoupling invariant: {@code SessionStatePoolStore.consume(state)} must
 * NOT remove the {@code state → FlowSecrets} association. The state is one-time-use, the
 * verifier and nonce are independently one-time-use, and an abandoned association ages out by
 * TTL/LRU.</p>
 */
public final class PipelineOrderingTest {

    private static final String CLIENT_NAME = "testClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 20;

    private static final String STATE_1 = "state-flow-1";
    private static final String STATE_2 = "state-flow-2";
    private static final String VERIFIER_1 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-flow1";
    private static final String VERIFIER_2 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-flow2";
    private static final String NONCE_1 = "nonce-flow-1";
    private static final String NONCE_2 = "nonce-flow-2";

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

    /** A callback context echoing the given state (one web context per pipeline stage, as in
     *  the real flow). */
    private CallContext callbackWithState(final String echoedState) {
        val webContext = MockWebContext.create();
        if (echoedState != null) {
            webContext.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, echoedState);
        }
        return new CallContext(webContext, sessionStore);
    }

    /** Redirect side for one flow: pool the state and associate both verifier and nonce. */
    private void redirectFlow(final String state, final String verifier, final String nonce) {
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        statePool.add(ctx, CLIENT_NAME, state);
        statePool.addFlowSecrets(ctx, CLIENT_NAME, state, verifier, nonce);
    }

    /**
     * Step 1 of the pipeline: the credentials extractor asks for the state key; the retriever
     * consumes the pool entry and returns the state.
     */
    private void extractorConsumesState(final String echoedState) {
        val result = retriever.retrieve(callbackWithState(echoedState),
            client.getStateSessionAttributeName(), client);
        assertTrue("state " + echoedState + " must validate", result.isPresent());
        assertEquals(new State(echoedState), result.get());
    }

    /**
     * Step 2 of the pipeline: the authenticator asks for the PKCE verifier key AFTER the state
     * has been consumed.
     */
    private Object authenticatorRetrievesVerifier(final String echoedState) {
        val result = retriever.retrieve(callbackWithState(echoedState),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("verifier for " + echoedState + " must be served even though its state is consumed",
            result.isPresent());
        return result.get();
    }

    /**
     * With two flows in flight, flow 1's callback IN THE REAL ORDER (state → verifier → nonce)
     * must recover flow 1's secrets — not flow 2's — even though the state is consumed first.
     * Then flow 2's callback must still recover its own secrets.
     */
    @Test
    public void realPipelineOrderRecoversEachFlowsOwnSecrets() {
        redirectFlow(STATE_1, VERIFIER_1, NONCE_1);
        redirectFlow(STATE_2, VERIFIER_2, NONCE_2);
        // Stock pac4j leaves the LATEST flow's verifier in the single slot — the wrong value for
        // flow 1's callback.
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier(VERIFIER_2));

        // --- Flow 1's callback, in pac4j's real order ---
        // 1. extractor: consume state 1 (must NOT delete the association).
        extractorConsumesState(STATE_1);
        // 2. authenticator: retrieve the verifier keyed by the echoed state — MUST be flow 1's.
        val verifier1 = authenticatorRetrievesVerifier(STATE_1);
        assertEquals("flow 1 must get its OWN verifier after its state was consumed",
            new CodeVerifier(VERIFIER_1), verifier1);
        // 3. profile creator: validate the nonce (the creator itself is covered by
        //    NoncePoolingTest).
        val nonce1 = statePool.consumeNonce(callbackWithState(STATE_1), CLIENT_NAME, STATE_1);
        assertTrue("flow 1's nonce must survive state + verifier consumption", nonce1.isPresent());
        assertEquals("flow 1 must get its OWN nonce", NONCE_1, nonce1.get());

        // --- Flow 2's callback, fully, afterwards ---
        extractorConsumesState(STATE_2);
        val verifier2 = authenticatorRetrievesVerifier(STATE_2);
        assertEquals("flow 2 must still get its OWN verifier", new CodeVerifier(VERIFIER_2), verifier2);
        val nonce2 = statePool.consumeNonce(callbackWithState(STATE_2), CLIENT_NAME, STATE_2);
        assertTrue(nonce2.isPresent());
        assertEquals("flow 2 must still get its OWN nonce", NONCE_2, nonce2.get());
    }

    /**
     * {@code consume(state)} must NOT remove the flow-secret association: consuming the state
     * first and only then asking for the verifier must still serve the pooled verifier.
     */
    @Test
    public void stateConsumptionLeavesAssociationIntact() {
        redirectFlow(STATE_1, VERIFIER_1, NONCE_1);

        assertTrue("state is consumed", statePool.consume(callbackWithState(STATE_1), CLIENT_NAME, STATE_1));
        assertTrue("state is one-time-use",
            statePool.consume(callbackWithState(STATE_1), CLIENT_NAME, STATE_1) == false);

        val verifier = statePool.consumeCodeVerifier(callbackWithState(STATE_1), CLIENT_NAME, STATE_1);
        assertTrue("the verifier association must SURVIVE state consumption", verifier.isPresent());
        assertEquals(VERIFIER_1, verifier.get());

        val nonce = statePool.consumeNonce(callbackWithState(STATE_1), CLIENT_NAME, STATE_1);
        assertTrue("the nonce association must SURVIVE state consumption", nonce.isPresent());
        assertEquals(NONCE_1, nonce.get());
    }

    /**
     * One-time use, fail closed: after flow 1's verifier is consumed, a second verifier
     * retrieval for flow 1's state must return EMPTY — and must NOT serve the shared single
     * session slot (which holds flow 2's verifier).
     */
    @Test
    public void secondVerifierRetrievalAfterConsumeFailsClosed() {
        redirectFlow(STATE_1, VERIFIER_1, NONCE_1);
        redirectFlow(STATE_2, VERIFIER_2, NONCE_2);
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier(VERIFIER_2)); // the shared slot holds flow 2's verifier

        extractorConsumesState(STATE_1);
        val first = retriever.retrieve(callbackWithState(STATE_1),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue(first.isPresent());
        assertEquals(new CodeVerifier(VERIFIER_1), first.get());

        val second = retriever.retrieve(callbackWithState(STATE_1),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("second retrieval must fail closed, not serve flow 2's slot value",
            second.isEmpty());
    }

    /**
     * Present-state-but-missing-association: the request HAS a state parameter but no pooled
     * association exists for it (unknown, expired, or already consumed) → empty, NOT the shared
     * session slot.
     */
    @Test
    public void presentStateButMissingAssociationFailsClosed() {
        redirectFlow(STATE_1, VERIFIER_1, NONCE_1); // only flow 1 has an association
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier(VERIFIER_1)); // slot even holds a plausible value; must not be served

        val unknown = retriever.retrieve(callbackWithState("state-never-registered"),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("unknown state with a state param present must fail closed", unknown.isEmpty());

        // Already-consumed variant: consume flow 1's verifier, then retry its state.
        assertTrue(statePool.consumeCodeVerifier(callbackWithState(STATE_1), CLIENT_NAME, STATE_1)
            .isPresent());
        val consumed = retriever.retrieve(callbackWithState(STATE_1),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("already-consumed association must fail closed", consumed.isEmpty());
    }

    /**
     * The stateless path ({@code withState=false}: NO state parameter on the request) is
     * unchanged: the raw session slot is served.
     */
    @Test
    public void statelessRequestStillUsesSessionSlot() {
        sessionStore.set(MockWebContext.create(), client.getCodeVerifierSessionAttributeName(),
            new CodeVerifier(VERIFIER_1));

        val result = retriever.retrieve(callbackWithState(null),
            client.getCodeVerifierSessionAttributeName(), client);

        assertTrue("withState=false (no state param) must still use the raw session slot",
            result.isPresent());
        assertEquals(new CodeVerifier(VERIFIER_1), result.get());
    }

    /**
     * Nonce one-time use is independent of verifier one-time use: consuming one must not consume
     * the sibling on the same entry, and each is independently fail-closed on reuse.
     */
    @Test
    public void verifierAndNonceAreIndependentlyOneTimeUse() {
        redirectFlow(STATE_1, VERIFIER_1, NONCE_1);
        extractorConsumesState(STATE_1);

        assertTrue(statePool.consumeCodeVerifier(callbackWithState(STATE_1), CLIENT_NAME, STATE_1)
            .isPresent());
        assertTrue("nonce survives verifier consumption on the same entry",
            statePool.consumeNonce(callbackWithState(STATE_1), CLIENT_NAME, STATE_1).isPresent());
        // Both now gone (entry dropped when it held nothing): second consumes are empty.
        assertTrue(statePool.consumeCodeVerifier(callbackWithState(STATE_1), CLIENT_NAME, STATE_1)
            .isEmpty());
        assertTrue(statePool.consumeNonce(callbackWithState(STATE_1), CLIENT_NAME, STATE_1).isEmpty());
    }

    /**
     * The association survives state consumption AND a serialize→deserialize hop, so the later
     * pipeline stages still recover the verifier from the deserialized holder.
     */
    @Test
    public void associationSurvivesStateConsumptionAcrossSerialization() throws Exception {
        redirectFlow(STATE_1, VERIFIER_1, NONCE_1);

        // Consume the state FIRST (real pipeline order), THEN round-trip the holder.
        assertTrue(statePool.consume(callbackWithState(STATE_1), CLIENT_NAME, STATE_1));

        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);
        val original = (StatePoolHolder) sessionStore.get(
            callbackWithState(null).webContext(), key).orElseThrow();
        val bytes = new java.io.ByteArrayOutputStream();
        try (val out = new java.io.ObjectOutputStream(bytes)) {
            out.writeObject(original);
        }
        final StatePoolHolder restored;
        try (val in = new java.io.ObjectInputStream(
                new java.io.ByteArrayInputStream(bytes.toByteArray()))) {
            restored = (StatePoolHolder) in.readObject();
        }
        sessionStore.set(callbackWithState(null).webContext(), key, restored);

        // The deserialized holder still serves flow 1's verifier even though its state is spent.
        val result = retriever.retrieve(callbackWithState(STATE_1),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("verifier must survive state consumption + serialization", result.isPresent());
        assertEquals(new CodeVerifier(VERIFIER_1), result.get());
        // And the spent state is still spent after the round-trip.
        assertFalse(statePool.consume(callbackWithState(STATE_1), CLIENT_NAME, STATE_1));
    }
}
