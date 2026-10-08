package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Issuer;
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
 * Client-name timing: the pool key embeds {@code client.getName()}, which pac4j only finalises
 * during {@code client.init()}. If the redirection action builder runs before any explicit init
 * (a test rig or manual wiring that bypasses {@code IndirectClient.getRedirectionAction}), the
 * pool must STILL be written under the same namespaced key the callback retriever will read.
 * Asserted end-to-end: drive the redirect builder WITHOUT calling {@code init()}, then confirm
 * the retriever finds the state.
 *
 * <p>A real {@link OIDCProviderMetadata} + {@link StaticOidcOpMetadataResolver} is used so no
 * network call is made.</p>
 */
public final class ClientNameTimingTest {

    private static OidcConfiguration newConfiguration() throws Exception {
        val metadata = new OIDCProviderMetadata(
            new Issuer("http://localhost:8080"),
            List.of(SubjectType.PUBLIC),
            new URI("http://localhost:8080/jwks"));
        metadata.applyDefaults();
        metadata.setAuthorizationEndpointURI(new URI("http://localhost:8080/auth"));
        metadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));

        val configuration = new OidcConfiguration();
        configuration.setClientId("clientId");
        configuration.setSecret("secret");
        configuration.setScope("openid");
        configuration.setPreferredJwsAlgorithm(JWSAlgorithm.RS256);
        // These tests exercise the state pool, not PKCE.
        configuration.setDisablePkce(true);
        val resolver = new StaticOidcOpMetadataResolver(configuration, metadata);
        // Register first: the resolver's init() validates the configuration, which requires the
        // resolver already be set. init() then populates the loaded metadata.
        configuration.setOpMetadataResolver(resolver);
        resolver.init();
        return configuration;
    }

    /**
     * No explicit name set and NO init() called before the redirect: the builder must force init
     * internally so the pool is keyed by the same (fallback) name the retriever later uses.
     */
    @Test
    public void redirectBeforeInitStillUsesCorrectNamespacedKey() throws Exception {
        val configuration = newConfiguration();
        val sessionStore = new MockSessionStore();
        val statePool = new StatePool(new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);
        configuration.setValueRetriever(new StatePoolValueRetriever(statePool));

        // No setName, and we deliberately do NOT call client.init().
        val client = new org.pac4j.oidc.client.OidcClient(configuration);
        client.setCallbackUrl("http://localhost:8080/callback");

        val builder = new StatePoolOidcRedirectionActionBuilder(client, statePool);

        // --- redirect side ---
        val redirectCtx = new CallContext(MockWebContext.create(), sessionStore);
        builder.getRedirectionAction(redirectCtx).orElseThrow();

        // Recover the generated state from the single slot to present it on the callback.
        val stateAttr = client.getStateSessionAttributeName();
        val stored = sessionStore.get(redirectCtx.webContext(), stateAttr);
        assertTrue("state single slot must be written", stored.isPresent());
        val stateValue = ((com.nimbusds.oauth2.sdk.id.State) stored.get()).getValue();

        // --- callback side ---
        val callbackWebContext = MockWebContext.create();
        callbackWebContext.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, stateValue);
        val callbackCtx = new CallContext(callbackWebContext, sessionStore);

        val result = configuration.getValueRetriever().retrieve(callbackCtx, stateAttr, client);
        assertTrue("retriever must find the pooled state written before init", result.isPresent());
    }

    /**
     * An explicit name set after construction is honoured on the redirect side once the builder
     * has forced init: the pool is namespaced under the explicit name, not the class-name
     * fallback.
     */
    @Test
    public void explicitlyNamedClientPoolsUnderItsName() throws Exception {
        val configuration = newConfiguration();
        val sessionStore = new MockSessionStore();
        val statePool = new StatePool(new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);
        configuration.setValueRetriever(new StatePoolValueRetriever(statePool));

        val client = new org.pac4j.oidc.client.OidcClient(configuration);
        client.setName("myNamedClient");
        client.setCallbackUrl("http://localhost:8080/callback");

        val builder = new StatePoolOidcRedirectionActionBuilder(client, statePool);
        val redirectCtx = new CallContext(MockWebContext.create(), sessionStore);
        builder.getRedirectionAction(redirectCtx).orElseThrow();

        assertTrue("pool must exist under the explicit client name",
            statePool.size(redirectCtx, "myNamedClient").isPresent());
        assertTrue("pool must be non-empty under the explicit client name",
            statePool.size(redirectCtx, "myNamedClient").orElse(0) > 0);
        assertEquals("no pool under the class-name fallback",
            0, statePool.size(redirectCtx, "OidcClient").orElse(0).intValue());
    }
}
