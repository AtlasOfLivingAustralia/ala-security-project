package au.org.ala.pac4j.oidc.statepool.mongo;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import lombok.val;
import org.bson.Document;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.utility.DockerImageName;

import java.time.Instant;
import java.util.Date;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link MongoStatePoolStore} against a Testcontainers MongoDB.
 *
 * @author pac4j state-pool contributors
 * @since 1.0.0
 */
public final class MongoStatePoolStoreTest {

    private static final String CLIENT_NAME = "mongoClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 5;

    private static MongoDBContainer mongo;
    private static MongoClient mongoClient;

    private MongoDatabase database;
    private MongoStatePoolStore store;
    private MockSessionStore sessionStore;
    private MockWebContext webContext;

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
        database = mongoClient.getDatabase("test_" + System.nanoTime());
        store = new MongoStatePoolStore(database);
        sessionStore = new MockSessionStore();
        webContext = MockWebContext.create();
        // Force session creation so resolveSessionId sees a real id.
        sessionStore.getSessionId(webContext, true);
    }

    @After
    public void tearDown() {
        database.drop();
    }

    private CallContext ctx() {
        return new CallContext(webContext, sessionStore);
    }

    private MongoCollection<Document> states() {
        return database.getCollection(MongoStatePoolStore.DEFAULT_STATE_COLLECTION);
    }

    private MongoCollection<Document> secrets() {
        return database.getCollection(MongoStatePoolStore.DEFAULT_SECRETS_COLLECTION);
    }

    /* 1 ----------------------------------------------------------------- */

    @Test
    public void addThenConsumeRoundTripConsumesExactlyOnce() {
        store.add(ctx(), CLIENT_NAME, "state-1", TTL_MILLIS, MAX_SIZE);

        assertTrue("first consume finds and removes the state",
            store.consume(ctx(), CLIENT_NAME, "state-1", TTL_MILLIS));
        assertFalse("second consume finds nothing (one-time use)",
            store.consume(ctx(), CLIENT_NAME, "state-1", TTL_MILLIS));
        assertEquals("the states collection is empty after consumption",
            0L, store.stateCount(ctx(), CLIENT_NAME));
    }

    @Test
    public void consumeUnknownStateReturnsFalse() {
        assertFalse(store.consume(ctx(), CLIENT_NAME, "never-registered", TTL_MILLIS));
    }

    @Test
    public void nullAndBlankInputsAreRejectedQuietly() {
        store.add(ctx(), CLIENT_NAME, null, TTL_MILLIS, MAX_SIZE);
        store.add(ctx(), CLIENT_NAME, "  ", TTL_MILLIS, MAX_SIZE);
        assertEquals(0L, store.stateCount(ctx(), CLIENT_NAME));
        assertFalse(store.consume(ctx(), CLIENT_NAME, null, TTL_MILLIS));
        assertFalse(store.consume(ctx(), CLIENT_NAME, "", TTL_MILLIS));
        assertTrue(store.consumeCodeVerifier(ctx(), CLIENT_NAME, null, TTL_MILLIS).isEmpty());
        assertTrue(store.consumeNonce(ctx(), CLIENT_NAME, " ", TTL_MILLIS).isEmpty());
        assertFalse(store.containsNonce(ctx(), CLIENT_NAME, null, TTL_MILLIS));
        assertFalse(store.consumeNonceByValue(ctx(), CLIENT_NAME, "", TTL_MILLIS));
        store.addFlowSecrets(ctx(), CLIENT_NAME, null, "v", "n", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "s", null, null, TTL_MILLIS, MAX_SIZE);
        assertEquals(0L, store.secretsCount(ctx(), CLIENT_NAME));
    }

    /* 3 ----------------------------------------------------------------- */

    @Test
    public void stateConsumeLeavesTheFlowSecretsAssociationIntact() {
        store.add(ctx(), CLIENT_NAME, "state-2", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "state-2", "verifier-2", "nonce-2",
            TTL_MILLIS, MAX_SIZE);

        assertTrue(store.consume(ctx(), CLIENT_NAME, "state-2", TTL_MILLIS));

        assertEquals(Optional.of("verifier-2"),
            store.consumeCodeVerifier(ctx(), CLIENT_NAME, "state-2", TTL_MILLIS));
        assertEquals(Optional.of("nonce-2"),
            store.consumeNonce(ctx(), CLIENT_NAME, "state-2", TTL_MILLIS));
    }

    /* 4 ----------------------------------------------------------------- */

    @Test
    public void verifierIsOneTimeUseAndLeavesNonceUntouched() {
        store.add(ctx(), CLIENT_NAME, "state-3", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "state-3", "verifier-3", "nonce-3",
            TTL_MILLIS, MAX_SIZE);

        assertEquals(Optional.of("verifier-3"),
            store.consumeCodeVerifier(ctx(), CLIENT_NAME, "state-3", TTL_MILLIS));
        assertTrue("the verifier cannot be consumed twice",
            store.consumeCodeVerifier(ctx(), CLIENT_NAME, "state-3", TTL_MILLIS).isEmpty());
        assertEquals("the sibling nonce on the same entry is untouched",
            Optional.of("nonce-3"),
            store.consumeNonce(ctx(), CLIENT_NAME, "state-3", TTL_MILLIS));
    }

    @Test
    public void entryIsDroppedOnceNoSecretsRemain() {
        store.add(ctx(), CLIENT_NAME, "state-4", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "state-4", "verifier-4", "nonce-4",
            TTL_MILLIS, MAX_SIZE);
        assertEquals(1L, store.secretsCount(ctx(), CLIENT_NAME));

        store.consumeCodeVerifier(ctx(), CLIENT_NAME, "state-4", TTL_MILLIS);
        assertEquals("the entry survives while the nonce remains",
            1L, store.secretsCount(ctx(), CLIENT_NAME));
        store.consumeNonce(ctx(), CLIENT_NAME, "state-4", TTL_MILLIS);
        assertEquals("the entry is dropped once nothing remains",
            0L, store.secretsCount(ctx(), CLIENT_NAME));
    }

    /* 5 ----------------------------------------------------------------- */

    @Test
    public void nonceByValueFindsAndRemovesTheNonce() {
        store.add(ctx(), CLIENT_NAME, "state-5", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "state-5", "verifier-5", "nonce-5",
            TTL_MILLIS, MAX_SIZE);

        assertTrue("the nonce is found by value",
            store.containsNonce(ctx(), CLIENT_NAME, "nonce-5", TTL_MILLIS));
        assertTrue("consume-by-value removes it",
            store.consumeNonceByValue(ctx(), CLIENT_NAME, "nonce-5", TTL_MILLIS));
        assertFalse("gone afterwards",
            store.containsNonce(ctx(), CLIENT_NAME, "nonce-5", TTL_MILLIS));
        assertFalse("and cannot be consumed twice",
            store.consumeNonceByValue(ctx(), CLIENT_NAME, "nonce-5", TTL_MILLIS));
        assertEquals("the sibling verifier survives the nonce consume",
            Optional.of("verifier-5"),
            store.consumeCodeVerifier(ctx(), CLIENT_NAME, "state-5", TTL_MILLIS));
    }

    /* 6 ----------------------------------------------------------------- */

    @Test
    public void expiredEntriesAreTreatedAsAbsentWithoutWaitingForTheTtlMonitor() {
        // Insert already-expired documents directly; the read-side expiresAt>now filter must hide them.
        final String sessionId = sessionStore.getSessionId(webContext, false).orElseThrow();
        states().insertOne(new Document()
            .append("sessionId", sessionId)
            .append("clientName", CLIENT_NAME)
            .append("state", "stale-state")
            .append("createdAt", Date.from(Instant.now().minusSeconds(600)))
            .append("expiresAt", Date.from(Instant.now().minusSeconds(300))));
        secrets().insertOne(new Document()
            .append("sessionId", sessionId)
            .append("clientName", CLIENT_NAME)
            .append("state", "stale-state")
            .append("codeVerifier", "stale-verifier")
            .append("nonce", "stale-nonce")
            .append("createdAt", Date.from(Instant.now().minusSeconds(600)))
            .append("expiresAt", Date.from(Instant.now().minusSeconds(300))));

        assertFalse("expired state is absent to consume",
            store.consume(ctx(), CLIENT_NAME, "stale-state", TTL_MILLIS));
        assertTrue("expired verifier is absent",
            store.consumeCodeVerifier(ctx(), CLIENT_NAME, "stale-state", TTL_MILLIS).isEmpty());
        assertTrue("expired nonce is absent",
            store.consumeNonce(ctx(), CLIENT_NAME, "stale-state", TTL_MILLIS).isEmpty());
        assertFalse("expired nonce is invisible to contains",
            store.containsNonce(ctx(), CLIENT_NAME, "stale-nonce", TTL_MILLIS));
        assertFalse("expired nonce is invisible to consume-by-value",
            store.consumeNonceByValue(ctx(), CLIENT_NAME, "stale-nonce", TTL_MILLIS));
        assertEquals("expired entries do not count toward the live size",
            0L, store.stateCount(ctx(), CLIENT_NAME));
    }

    /* 7 ----------------------------------------------------------------- */

    @Test
    public void maxSizeBoundEvictsTheOldestEntries() throws InterruptedException {
        for (int i = 0; i < MAX_SIZE + 1; i++) {
            store.add(ctx(), CLIENT_NAME, "lru-state-" + i, TTL_MILLIS, MAX_SIZE);
            Thread.sleep(2); // distinct createdAt for a deterministic oldest
        }

        assertEquals("the pool is bounded at maxSize",
            MAX_SIZE, store.stateCount(ctx(), CLIENT_NAME));
        assertFalse("the oldest entry was evicted",
            store.consume(ctx(), CLIENT_NAME, "lru-state-0", TTL_MILLIS));
        assertTrue("the newest entry survived",
            store.consume(ctx(), CLIENT_NAME, "lru-state-" + MAX_SIZE, TTL_MILLIS));
    }

    /* 8 ----------------------------------------------------------------- */

    /** MockSessionStore pinned to a fixed session id. */
    private static final class FixedIdSessionStore extends MockSessionStore {
        private final String fixedId;

        FixedIdSessionStore(final String fixedId) {
            this.fixedId = fixedId;
        }

        @Override
        public Optional<String> getSessionId(final org.pac4j.core.context.WebContext context,
                                             final boolean createSession) {
            return Optional.of(fixedId);
        }
    }

    @Test
    public void sameStateValueUnderTwoSessionsDoesNotCollide() {
        sessionStore = new FixedIdSessionStore("session-A");
        webContext = MockWebContext.create();
        val otherSessionStore = new FixedIdSessionStore("session-B");
        val otherWebContext = MockWebContext.create();
        val otherCtx = new CallContext(otherWebContext, otherSessionStore);
        assertFalse(sessionStore.getSessionId(webContext, false).orElseThrow()
            .equals(otherSessionStore.getSessionId(otherWebContext, false).orElseThrow()));

        store.add(ctx(), CLIENT_NAME, "shared-state", TTL_MILLIS, MAX_SIZE);
        store.add(otherCtx, CLIENT_NAME, "shared-state", TTL_MILLIS, MAX_SIZE);

        assertTrue("session A consumes its own copy",
            store.consume(ctx(), CLIENT_NAME, "shared-state", TTL_MILLIS));
        assertTrue("session B's identical state value is unaffected",
            store.consume(otherCtx, CLIENT_NAME, "shared-state", TTL_MILLIS));
        assertFalse("and now both are gone",
            store.consume(otherCtx, CLIENT_NAME, "shared-state", TTL_MILLIS));
    }

    @Test
    public void poolsAreNamespacedPerClient() {
        store.add(ctx(), CLIENT_NAME, "state-6", TTL_MILLIS, MAX_SIZE);

        assertFalse("another client cannot see the state",
            store.consume(ctx(), "otherClient", "state-6", TTL_MILLIS));
        assertTrue("the owning client still can",
            store.consume(ctx(), CLIENT_NAME, "state-6", TTL_MILLIS));
    }

    /* misc --------------------------------------------------------------- */

    @Test
    public void addIsIdempotentForTheSameStateValue() {
        store.add(ctx(), CLIENT_NAME, "dup-state", TTL_MILLIS, MAX_SIZE);
        store.add(ctx(), CLIENT_NAME, "dup-state", TTL_MILLIS, MAX_SIZE);

        assertEquals("re-adding the same state refreshes rather than duplicates",
            1L, store.stateCount(ctx(), CLIENT_NAME));
        assertTrue(store.consume(ctx(), CLIENT_NAME, "dup-state", TTL_MILLIS));
    }

    @Test
    public void addFlowSecretsMergesNullFieldsAsLeaveUntouched() {
        store.add(ctx(), CLIENT_NAME, "state-7", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "state-7", "verifier-7", null,
            TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx(), CLIENT_NAME, "state-7", null, "nonce-7",
            TTL_MILLIS, MAX_SIZE);

        assertEquals("the verifier survived the second (nonce-only) upsert",
            Optional.of("verifier-7"),
            store.consumeCodeVerifier(ctx(), CLIENT_NAME, "state-7", TTL_MILLIS));
        assertEquals("the nonce was added by the second upsert",
            Optional.of("nonce-7"),
            store.consumeNonce(ctx(), CLIENT_NAME, "state-7", TTL_MILLIS));
    }

    @Test
    public void indexesAreCreatedByTheConstructor() {
        val names = new java.util.ArrayList<String>();
        for (val index : states().listIndexes()) {
            names.add(index.getString("name"));
        }
        assertTrue("unique (sessionId, clientName, state) index exists",
            names.stream().anyMatch(n -> n.contains("sessionId") && n.contains("state")));
        assertTrue("TTL index on expiresAt exists",
            names.stream().anyMatch(n -> n.contains("expiresAt")));
    }
}
