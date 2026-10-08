package au.org.ala.pac4j.oidc.statepool.mongo;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import lombok.val;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import au.org.ala.pac4j.oidc.statepool.StatePool;
import au.org.ala.pac4j.oidc.statepool.StatePoolOidcClient;
import au.org.ala.pac4j.oidc.statepool.StatePoolOidcRedirectionActionBuilder;
import au.org.ala.pac4j.oidc.statepool.StatePoolValueRetriever;
import org.pac4j.core.context.session.MockSessionStore;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.utility.DockerImageName;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * End-to-end proof that a {@link StatePoolOidcClient} backed by {@link MongoStatePoolStore}
 * records state + verifier on redirect and recovers the verifier after state consumption on
 * callback. No network: OP metadata is static.
 *
 * @author pac4j state-pool contributors
 * @since 1.0.0
 */
public final class MongoStatePoolStoreIntegrationTest {

    private static final String CLIENT_NAME = "mongoE2EClient";

    private static MongoDBContainer mongo;
    private static MongoClient mongoClient;

    private MongoDatabase database;
    private MongoStatePoolStore store;
    private MockSessionStore sessionStore;

    @BeforeClass
    public static void startMongo() {
        mongo = new MongoDBContainer(DockerImageName.parse("mongo:6.0.26"));
        mongo.start();
        mongoClient = MongoClients.create(mongo.getConnectionString());
    }

    @AfterClass
    public static void stopMongo() {
        if (mongoClient != null) {
            mongoClient.close();
        }
        if (mongo != null) {
            mongo.stop();
        }
    }

    @Before
    public void setUp() {
        database = mongoClient.getDatabase("e2e_" + System.nanoTime());
        store = new MongoStatePoolStore(database);
        sessionStore = new MockSessionStore();
    }

    @After
    public void tearDown() {
        database.drop();
    }

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

    private static OidcConfiguration configuration(final OIDCProviderMetadata metadata) {
        val configuration = new OidcConfiguration();
        configuration.setClientId("clientId");
        configuration.setSecret("secret");
        configuration.setScope("openid");
        configuration.setPreferredJwsAlgorithm(JWSAlgorithm.RS256);
        configuration.setDisablePkce(false);
        configuration.setPkceMethod(com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod.S256);
        val resolver = new StaticOidcOpMetadataResolver(configuration, metadata);
        configuration.setOpMetadataResolver(resolver);
        resolver.init();
        return configuration;
    }

    @Test
    public void statePoolOidcClientFlowRunsAgainstMongo() throws Exception {
        val configuration = configuration(metadata());
        val client = new StatePoolOidcClient(configuration, store,
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);
        client.setName(CLIENT_NAME);
        client.setCallbackUrl("http://localhost:8080/callback");
        client.init();

        val statePool = client.getStatePool();

        val redirectCtx = new CallContext(MockWebContext.create(), sessionStore);
        val builder = new StatePoolOidcRedirectionActionBuilder(client, statePool, true, false);
        builder.getRedirectionAction(redirectCtx).orElseThrow();

        val stateValue = ((com.nimbusds.oauth2.sdk.id.State) sessionStore
            .get(redirectCtx.webContext(), client.getStateSessionAttributeName())
            .orElseThrow()).getValue();
        val slotVerifier = (CodeVerifier) sessionStore
            .get(redirectCtx.webContext(), client.getCodeVerifierSessionAttributeName())
            .orElseThrow();

        assertTrue("the state landed in Mongo",
            store.stateCount(redirectCtx, CLIENT_NAME) == 1L);

        val callbackWebContext = MockWebContext.create();
        callbackWebContext.addRequestParameter(StatePoolValueRetriever.STATE_PARAM, stateValue);
        val retriever = configuration.getValueRetriever();

        val consumedState = retriever.retrieve(
            new CallContext(callbackWebContext, sessionStore),
            client.getStateSessionAttributeName(), client);
        assertTrue("the pooled state validates", consumedState.isPresent());

        val verifier = retriever.retrieve(
            new CallContext(callbackWebContext, sessionStore),
            client.getCodeVerifierSessionAttributeName(), client);
        assertTrue("the verifier survives state consumption", verifier.isPresent());
        assertEquals("and equals what pac4j stored for this flow", slotVerifier, verifier.get());

        assertTrue("state cannot be replayed",
            retriever.retrieve(new CallContext(callbackWebContext, sessionStore),
                client.getStateSessionAttributeName(), client).isEmpty());
        assertEquals(Optional.empty(),
            statePool.consumeCodeVerifier(new CallContext(callbackWebContext, sessionStore),
                CLIENT_NAME, stateValue));
    }
}
