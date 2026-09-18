package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.val;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;

import java.net.URI;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * End-to-end tests that the redirect builder ({@link StatePoolOidcRedirectionActionBuilder})
 * records the per-flow PKCE {@code code_verifier} (on by default) and {@code nonce} (opt-in)
 * associations alongside the pooled state. Real OP metadata and a
 * {@link StaticOidcOpMetadataResolver} are used so no network call is made.
 */
public final class StatePoolBuilderSecretsTest {

    private static final String CLIENT_NAME = "builderClient";

    private static OIDCProviderMetadata metadata() throws Exception {
        val metadata = new OIDCProviderMetadata(
            new Issuer("http://localhost:8080"),
            List.of(SubjectType.PUBLIC),
            new URI("http://localhost:8080/jwks"));
        metadata.applyDefaults();
        metadata.setAuthorizationEndpointURI(new URI("http://localhost:8080/auth"));
        metadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));
        return metadata;
    }

    private static OidcConfiguration configuration(final OIDCProviderMetadata metadata,
                                                   final boolean disablePkce,
                                                   final boolean useNonce) {
        val configuration = new OidcConfiguration();
        configuration.setClientId("clientId");
        configuration.setSecret("secret");
        configuration.setScope("openid");
        configuration.setPreferredJwsAlgorithm(JWSAlgorithm.RS256);
        configuration.setDisablePkce(disablePkce);
        // Pin the PKCE method explicitly: findPkceMethod() must not depend on the OP metadata
        // advertising code_challenge_methods (our minimal static metadata omits it).
        if (!disablePkce) {
            configuration.setPkceMethod(com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod.S256);
        }
        configuration.setUseNonce(useNonce);
        val resolver = new StaticOidcOpMetadataResolver(configuration, metadata);
        configuration.setOpMetadataResolver(resolver);
        resolver.init();
        return configuration;
    }

    /** Run the redirect side and return the generated state value. */
    private static String runRedirect(final org.pac4j.oidc.client.OidcClient client,
                                      final StatePool statePool,
                                      final MockSessionStore sessionStore,
                                      final boolean pkcePooling, final boolean noncePooling) {
        val builder = new StatePoolOidcRedirectionActionBuilder(
            client, statePool, pkcePooling, noncePooling);
        val redirectCtx = new CallContext(MockWebContext.create(), sessionStore);
        builder.getRedirectionAction(redirectCtx).orElseThrow();
        val stored = sessionStore.get(redirectCtx.webContext(), client.getStateSessionAttributeName());
        assertTrue("state single slot must be written", stored.isPresent());
        return ((com.nimbusds.oauth2.sdk.id.State) stored.get()).getValue();
    }

    /**
     * With PKCE enabled and pooling on (default), the builder records the generated verifier
     * against the flow's state, and the retriever recovers it on the callback.
     */
    @Test
    public void builderRecordsPkceVerifierForTheFlow() throws Exception {
        val configuration = configuration(metadata(), false, false); // PKCE on, nonce off
        val sessionStore = new MockSessionStore();
        val statePool = new StatePool(new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);
        val retriever = new StatePoolValueRetriever(statePool); // PKCE pooling on

        val client = new org.pac4j.oidc.client.OidcClient(configuration);
        client.setName(CLIENT_NAME);
        client.setCallbackUrl("http://localhost:8080/callback");

        val stateValue = runRedirect(client, statePool, sessionStore, true, false);

        // The builder must have written the single slot AND associated the verifier.
        val slotVerifier = sessionStore.get(
            new CallContext(MockWebContext.create(), sessionStore).webContext(),
            client.getCodeVerifierSessionAttributeName());
        assertTrue("pac4j's single verifier slot is still written (additive)", slotVerifier.isPresent());

        // Callback: the retriever serves the pooled verifier for the echoed state.
        val callbackWebContext = MockWebContext.create();
        callbackWebContext.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, stateValue);
        val result = retriever.retrieve(new CallContext(callbackWebContext, sessionStore),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("the pooled verifier is served for the echoed state", result.isPresent());
        assertTrue(result.get() instanceof CodeVerifier);
        assertEquals("the pooled verifier equals what pac4j stored in the slot",
            slotVerifier.get(), result.get());
    }

    /**
     * With {@code useNonce} on and nonce pooling enabled, the builder records the generated nonce
     * against the flow's state.
     */
    @Test
    public void builderRecordsNonceForTheFlowWhenEnabled() throws Exception {
        val configuration = configuration(metadata(), true, true); // PKCE off, nonce on
        val sessionStore = new MockSessionStore();
        val statePool = new StatePool(new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);

        val client = new org.pac4j.oidc.client.OidcClient(configuration);
        client.setName(CLIENT_NAME);
        client.setCallbackUrl("http://localhost:8080/callback");

        val stateValue = runRedirect(client, statePool, sessionStore, false, true);

        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        val slotNonce = sessionStore.get(ctx.webContext(), client.getNonceSessionAttributeName());
        assertTrue("pac4j's single nonce slot is still written (additive)", slotNonce.isPresent());
        val nonceValue = (String) slotNonce.get();
        assertTrue("the nonce is pooled under the flow's client",
            statePool.containsNonce(ctx, CLIENT_NAME, nonceValue));
        assertEquals("the nonce is recorded against the flow's state",
            java.util.Optional.of(nonceValue),
            statePool.consumeNonce(ctx, CLIENT_NAME, stateValue));
    }

    /**
     * With nonce pooling DISABLED (the default), the builder does NOT record the nonce even when
     * {@code useNonce} is on.
     */
    @Test
    public void builderSkipsNonceWhenPoolingDisabled() throws Exception {
        val configuration = configuration(metadata(), true, true); // PKCE off, nonce on
        val sessionStore = new MockSessionStore();
        val statePool = new StatePool(new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);

        val client = new org.pac4j.oidc.client.OidcClient(configuration);
        client.setName(CLIENT_NAME);
        client.setCallbackUrl("http://localhost:8080/callback");

        val stateValue = runRedirect(client, statePool, sessionStore, false, false);

        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        assertTrue("no nonce association is recorded when pooling is disabled",
            statePool.consumeNonce(ctx, CLIENT_NAME, stateValue).isEmpty());
    }

    /**
     * Two concurrent flows through the builder each keep their own verifier: neither clobbers
     * the other, and each callback recovers its own.
     */
    @Test
    public void twoConcurrentFlowsKeepDistinctVerifiers() throws Exception {
        val configuration = configuration(metadata(), false, false); // PKCE on
        val sessionStore = new MockSessionStore();
        val statePool = new StatePool(new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);
        val retriever = new StatePoolValueRetriever(statePool);

        val client = new org.pac4j.oidc.client.OidcClient(configuration);
        client.setName(CLIENT_NAME);
        client.setCallbackUrl("http://localhost:8080/callback");

        val builder = new StatePoolOidcRedirectionActionBuilder(client, statePool, true, false);

        // Flow 1 redirect.
        val ctx1 = new CallContext(MockWebContext.create(), sessionStore);
        builder.getRedirectionAction(ctx1).orElseThrow();
        val state1 = ((com.nimbusds.oauth2.sdk.id.State) sessionStore
            .get(ctx1.webContext(), client.getStateSessionAttributeName()).orElseThrow()).getValue();
        val verifier1 = (CodeVerifier) sessionStore
            .get(ctx1.webContext(), client.getCodeVerifierSessionAttributeName()).orElseThrow();

        // Flow 2 redirect (clobbers the single slot, but not the pool).
        val ctx2 = new CallContext(MockWebContext.create(), sessionStore);
        builder.getRedirectionAction(ctx2).orElseThrow();
        val state2 = ((com.nimbusds.oauth2.sdk.id.State) sessionStore
            .get(ctx2.webContext(), client.getStateSessionAttributeName()).orElseThrow()).getValue();

        // Callback for flow 1 recovers verifier1 even though the single slot now holds flow 2's.
        val cb1 = MockWebContext.create();
        cb1.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, state1);
        val r1 = retriever.retrieve(new CallContext(cb1, sessionStore),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue(r1.isPresent());
        assertEquals("flow 1 recovers its own verifier despite the clobbered slot",
            verifier1, r1.get());

        // Callback for flow 2 still works.
        val cb2 = MockWebContext.create();
        cb2.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, state2);
        val r2 = retriever.retrieve(new CallContext(cb2, sessionStore),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("flow 2's verifier is still available", r2.isPresent());
    }
}
