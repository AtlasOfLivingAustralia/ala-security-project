package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.val;
import org.junit.Before;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.core.profile.factory.ProfileManagerFactory;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.exceptions.OidcException;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;
import org.pac4j.oidc.profile.creator.TokenValidator;

import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Tests for nonce pooling (opt-in, default OFF) with {@code useNonce=true}: the expected nonce
 * is resolved from the pool by the ID token's nonce claim (membership-checked and consumed
 * one-time), then Nimbus's TokenValidator enforces claim equality. Covers: a pooled nonce
 * validates and consumes; an unknown claim fails closed; a consumed nonce cannot be replayed;
 * the flag off keeps stock single-slot behaviour; concurrent flows' nonces do not clobber.
 *
 * <p>ID tokens are unsigned {@link PlainJWT}s and the {@link TokenValidator} is stubbed to parse
 * claims and enforce nonce equality without a live OP.</p>
 */
public final class NoncePoolingTest {

    private static final String CLIENT_NAME = "testClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 20;

    private StatePool statePool;
    private MockSessionStore sessionStore;
    private OidcConfiguration configuration;
    private OidcClient client;

    /**
     * A {@link TokenValidator} that enforces nonce equality like Nimbus's {@code
     * IDTokenValidator} but skips signature verification, so unsigned {@link PlainJWT} ID tokens
     * can be used.
     */
    private static final class NonceEnforcingTokenValidator extends TokenValidator {
        NonceEnforcingTokenValidator(final OidcConfiguration cfg, final OIDCProviderMetadata md) {
            super(cfg, md);
        }

        @Override
        public IDTokenClaimsSet validateIdToken(final JWT idToken, final Nonce expectedNonce)
            throws BadJOSEException {
            try {
                val claims = IDTokenClaimsSet.parse(idToken.getJWTClaimsSet().toString());
                val actual = claims.getNonce();
                if (expectedNonce != null && !expectedNonce.equals(actual)) {
                    throw new BadJOSEException("Unexpected nonce: " + actual);
                }
                return claims;
            } catch (final java.text.ParseException | com.nimbusds.oauth2.sdk.ParseException e) {
                throw new BadJOSEException("cannot parse ID token: " + e.getMessage());
            }
        }
    }

    @Before
    public void setUp() throws Exception {
        statePool = new StatePool(new SessionStatePoolStore(), TTL_MILLIS, MAX_SIZE);
        sessionStore = new MockSessionStore();

        // Real OP metadata (no network, no mocking framework).
        val metadata = new OIDCProviderMetadata(
            new Issuer("http://localhost:8080"),
            List.of(SubjectType.PUBLIC),
            new URI("http://localhost:8080/jwks"));
        metadata.applyDefaults();
        metadata.setAuthorizationEndpointURI(new URI("http://localhost:8080/auth"));
        metadata.setIDTokenJWSAlgs(List.of(JWSAlgorithm.RS256));

        configuration = new OidcConfiguration();
        configuration.setClientId("clientId");
        configuration.setSecret("secret");
        configuration.setScope("openid");
        configuration.setPreferredJwsAlgorithm(JWSAlgorithm.RS256);
        configuration.setUseNonce(true);
        configuration.setDisablePkce(true); // isolate nonce pooling from PKCE

        // Install the nonce-enforcing (signature-skipping) validator so no OP keys or network
        // are needed.
        val resolver = new StaticOidcOpMetadataResolver(configuration, metadata) {
            @Override
            protected TokenValidator createTokenValidator() {
                return new NonceEnforcingTokenValidator(configuration, metadata);
            }
        };
        configuration.setOpMetadataResolver(resolver);
        resolver.init();
    }

    /** Build credentials carrying an ID token with the given nonce claim. */
    private static OidcCredentials credentialsWithNonce(final String nonceValue) {
        val claims = new JWTClaimsSet.Builder()
            .issuer("http://op")
            .audience("clientId")
            .issueTime(new Date())
            .expirationTime(new Date(new Date().getTime() + 60000))
            .subject("subject")
            .claim("nonce", nonceValue)
            .build();
        val credentials = new OidcCredentials();
        credentials.setIdToken(new PlainJWT(claims).serialize());
        credentials.setAccessToken(
            new com.nimbusds.oauth2.sdk.token.BearerAccessToken("at").toJSONObject());
        return credentials;
    }

    /** Redirect side for one flow: pool the state and associate its nonce. */
    private void redirectFlow(final String stateValue, final String nonceValue) {
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        statePool.add(ctx, CLIENT_NAME, stateValue);
        statePool.addFlowSecrets(ctx, CLIENT_NAME, stateValue, null, nonceValue);
    }

    private StatePoolOidcProfileCreator poolingCreator() {
        return new StatePoolOidcProfileCreator(configuration, client, statePool, true);
    }

    private OidcClient namedClient() {
        val c = new OidcClient(configuration);
        c.setName(CLIENT_NAME);
        return c;
    }

    /**
     * An ID token whose nonce claim is in the pool validates and is consumed (one-time use).
     */
    @Test
    public void pooledNonceValidatesAndIsConsumed() {
        client = namedClient();
        redirectFlow("state-1", "nonce-1");
        val creator = poolingCreator();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        val profile = creator.create(ctx, credentialsWithNonce("nonce-1"));
        assertTrue("a pooled nonce must validate and produce a profile", profile.isPresent());
        assertEquals("subject", profile.get().getId());

        assertThrows(OidcException.class, () -> creator.create(
            new CallContext(MockWebContext.create(), sessionStore), credentialsWithNonce("nonce-1")));
    }

    /**
     * An ID token whose nonce claim is NOT in the pool fails closed.
     */
    @Test
    public void unknownNonceClaimFailsClosed() {
        client = namedClient();
        redirectFlow("state-1", "nonce-1");
        val creator = poolingCreator();

        assertThrows("an un-pooled nonce claim must be rejected", OidcException.class,
            () -> creator.create(new CallContext(MockWebContext.create(), sessionStore),
                credentialsWithNonce("attacker-nonce")));
    }

    /**
     * A nonce consumed by one callback cannot be replayed by another (replay protection).
     */
    @Test
    public void consumedNonceCannotBeReplayed() {
        client = namedClient();
        redirectFlow("state-1", "nonce-1");
        val creator = poolingCreator();

        assertTrue(creator.create(new CallContext(MockWebContext.create(), sessionStore),
            credentialsWithNonce("nonce-1")).isPresent());
        // Replay the exact same ID token.
        assertThrows(OidcException.class,
            () -> creator.create(new CallContext(MockWebContext.create(), sessionStore),
                credentialsWithNonce("nonce-1")));
    }

    /**
     * With the flag OFF the creator behaves like stock pac4j: the expected nonce is read from
     * the single session slot and any pooled entry is ignored.
     */
    @Test
    public void flagOffUsesStockSingleSlotBehaviour() {
        client = namedClient();
        sessionStore.set(MockWebContext.create(), client.getNonceSessionAttributeName(), "slot-nonce");
        redirectFlow("state-1", "pooled-nonce");

        val stockCreator = new StatePoolOidcProfileCreator(configuration, client, statePool, false);
        val profile = stockCreator.create(new CallContext(MockWebContext.create(), sessionStore),
            credentialsWithNonce("slot-nonce"));
        assertTrue("flag off → single-slot nonce validates", profile.isPresent());
    }

    /**
     * Concurrent flows' nonces do not clobber each other: each callback validates against its
     * own pooled nonce, and consuming one does not affect the other.
     */
    @Test
    public void concurrentFlowsNoncesDoNotClobber() throws Exception {
        client = namedClient();
        redirectFlow("state-1", "nonce-1");
        redirectFlow("state-2", "nonce-2");
        val creator = poolingCreator();
        creator.init();

        val executor = Executors.newFixedThreadPool(2);
        try {
            val first = executor.submit(() -> creator.create(
                new CallContext(MockWebContext.create(), sessionStore),
                credentialsWithNonce("nonce-1")));
            val second = executor.submit(() -> creator.create(
                new CallContext(MockWebContext.create(), sessionStore),
                credentialsWithNonce("nonce-2")));

            assertTrue(first.get(5, TimeUnit.SECONDS).isPresent());
            assertTrue(second.get(5, TimeUnit.SECONDS).isPresent());
        } finally {
            executor.shutdownNow();
        }
        // Both are now consumed.
        assertThrows(OidcException.class,
            () -> creator.create(new CallContext(MockWebContext.create(), sessionStore),
                credentialsWithNonce("nonce-2")));
    }

    /** The overlay changes only the delegate's nonce read and preserves the original context. */
    @Test
    public void pooledNonceUsesRequestLocalSessionOverlay() {
        client = namedClient();
        redirectFlow("state-1", "pooled-nonce");
        val webContext = MockWebContext.create();
        val nonceKey = client.getNonceSessionAttributeName();
        sessionStore.set(webContext, nonceKey, "real-session-nonce");
        sessionStore.set(webContext, "unrelated", "before");
        ProfileManagerFactory profileManagerFactory = (context, store) -> null;
        val ctx = new CallContext(webContext, sessionStore, profileManagerFactory);

        val creator = new StatePoolOidcProfileCreator(configuration, client, statePool, true,
            (delegateContext, credentials) -> {
                assertSame(webContext, delegateContext.webContext());
                assertSame(profileManagerFactory, delegateContext.profileManagerFactory());
                assertEquals("pooled-nonce", delegateContext.sessionStore()
                    .get(webContext, nonceKey).orElse(null));
                assertEquals("real-session-nonce", sessionStore.get(webContext, nonceKey).orElse(null));
                assertEquals("before", delegateContext.sessionStore()
                    .get(webContext, "unrelated").orElse(null));
                delegateContext.sessionStore().set(webContext, "unrelated", "after");
                return Optional.empty();
            });

        assertTrue(creator.create(ctx, credentialsWithNonce("pooled-nonce")).isEmpty());
        assertEquals("real-session-nonce", sessionStore.get(webContext, nonceKey).orElse(null));
        assertEquals("after", sessionStore.get(webContext, "unrelated").orElse(null));
        assertFalse(statePool.containsNonce(ctx, CLIENT_NAME, "pooled-nonce"));
    }

    /** Missing and blank nonce claims are rejected before delegation. */
    @Test
    public void missingAndBlankNonceClaimsFailClosed() {
        client = namedClient();
        val creator = poolingCreator();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        assertThrows(OidcException.class,
            () -> creator.create(ctx, credentialsWithNonce(null)));
        assertThrows(OidcException.class,
            () -> creator.create(ctx, credentialsWithNonce(" ")));
        assertThrows(OidcException.class,
            () -> creator.create(ctx, new OidcCredentials()));
    }

    /** Nonce-disabled and refresh-bypass calls reach the delegate with the original context. */
    @Test
    public void nonceValidationBypassDelegatesWithoutPoolResolution() {
        client = namedClient();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        val delegateCalls = new int[] {0};
        val creator = new StatePoolOidcProfileCreator(configuration, client, statePool, true,
            (delegateContext, credentials) -> {
                assertSame(ctx, delegateContext);
                delegateCalls[0]++;
                return Optional.empty();
            });

        configuration.setUseNonce(false);
        creator.create(ctx, credentialsWithNonce("not-pooled"));

        configuration.setUseNonce(true);
        configuration.setUseNonceOnRefresh(false);
        val refreshedCredentials = credentialsWithNonce("also-not-pooled");
        refreshedCredentials.setRefreshedCredentials(true);
        creator.create(ctx, refreshedCredentials);

        assertEquals(2, delegateCalls[0]);
    }

    /**
     * Nonce pooling is OFF by default on the client.
     */
    @Test
    public void clientFlagDefaultsOffAndInstallsProfileCreatorWhenEnabled() throws Exception {
        val cfg = new OidcConfiguration();
        cfg.setClientId("clientId");
        cfg.setSecret("secret");
        val poolClient = new StatePoolOidcClient(cfg);
        assertFalse("nonce pooling must default to OFF", poolClient.isNoncePoolingEnabled());

        poolClient.setNoncePoolingEnabled(true);
        assertTrue(poolClient.isNoncePoolingEnabled());
    }

    /** A profile creator configured by the caller is decorated, invoked, and not double-wrapped. */
    @Test
    public void clientPreservesConfiguredProfileCreator() {
        val delegateCalls = new int[] {0};
        val customCreator = (org.pac4j.core.profile.creator.ProfileCreator) (ctx, credentials) -> {
            delegateCalls[0]++;
            return Optional.empty();
        };
        val poolClient = new StatePoolOidcClient(configuration);
        poolClient.setName(CLIENT_NAME);
        poolClient.setCallbackUrl("http://localhost/callback");
        poolClient.setProfileCreator(customCreator);
        poolClient.setNoncePoolingEnabled(true);

        poolClient.init();

        assertTrue(poolClient.getProfileCreator() instanceof StatePoolOidcProfileCreator);
        val wrapper = (StatePoolOidcProfileCreator) poolClient.getProfileCreator();
        assertSame(customCreator, wrapper.getDelegate());

        configuration.setUseNonce(false);
        wrapper.create(new CallContext(MockWebContext.create(), sessionStore),
            credentialsWithNonce("not-pooled"));
        assertEquals(1, delegateCalls[0]);

        poolClient.internalInit(false);
        assertSame("reinitialization must not add another decorator",
            wrapper, poolClient.getProfileCreator());
    }

    /** With no configured creator, the client decorates pac4j's stock OIDC creator. */
    @Test
    public void clientWrapsStockProfileCreatorByDefault() {
        val poolClient = new StatePoolOidcClient(configuration);
        poolClient.setName(CLIENT_NAME);
        poolClient.setCallbackUrl("http://localhost/callback");
        poolClient.setNoncePoolingEnabled(true);

        poolClient.init();

        assertTrue(poolClient.getProfileCreator() instanceof StatePoolOidcProfileCreator);
        val wrapper = (StatePoolOidcProfileCreator) poolClient.getProfileCreator();
        assertTrue(wrapper.getDelegate() instanceof OidcProfileCreator);
    }

    /** TTL applies to nonce associations: an expired pooled nonce is rejected. */
    @Test
    public void expiredNonceIsRejected() throws InterruptedException {
        client = namedClient();
        val shortPool = new StatePool(new SessionStatePoolStore(), 50L, MAX_SIZE);
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        shortPool.add(ctx, CLIENT_NAME, "state-exp");
        shortPool.addFlowSecrets(ctx, CLIENT_NAME, "state-exp", null, "nonce-exp");
        val creator = new StatePoolOidcProfileCreator(configuration, client, shortPool, true);

        Thread.sleep(90L);

        assertThrows(OidcException.class,
            () -> creator.create(new CallContext(MockWebContext.create(), sessionStore),
                credentialsWithNonce("nonce-exp")));
    }
}
