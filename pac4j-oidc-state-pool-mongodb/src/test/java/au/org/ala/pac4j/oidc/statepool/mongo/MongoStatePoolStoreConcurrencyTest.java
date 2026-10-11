package au.org.ala.pac4j.oidc.statepool.mongo;

import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;
import lombok.val;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.MockSessionStore;
import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.utility.DockerImageName;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Cluster-safety proof for {@link MongoStatePoolStore}: N threads racing the same
 * (sessionId, clientName, state) through separate store instances must yield exactly one
 * successful consume. Each racer uses its own {@link MongoClient}; the only shared state is the
 * MongoDB server. The same race is repeated for verifier and nonce-by-value consumes.
 *
 * @author pac4j state-pool contributors
 * @since 1.0.0
 */
public final class MongoStatePoolStoreConcurrencyTest {

    private static final String CLIENT_NAME = "raceClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 50;
    private static final int RACERS = 16;
    private static final int ROUNDS = 5;
    private static final String SHARED_SESSION_ID = "shared-session-across-nodes";

    private static MongoDBContainer mongo;
    private static MongoClient sharedClient;

    private MongoDatabase database;

    @BeforeClass
    public static void startMongo() {
        mongo = new MongoDBContainer(DockerImageName.parse("mongo:6.0.26"));
        mongo.start();
        sharedClient = MongoClients.create(mongo.getConnectionString());
    }

    @AfterClass
    public static void stopMongo() {
        if (sharedClient != null) {
            sharedClient.close();
        }
        if (mongo != null) {
            mongo.stop();
        }
    }

    @Before
    public void setUp() {
        database = sharedClient.getDatabase("race_" + System.nanoTime());
        // Create indexes once via a throwaway store instance.
        new MongoStatePoolStore(database);
    }

    @After
    public void tearDown() {
        database.drop();
    }

    /**
     * One simulated node: own {@link MongoClient}, own store, session store reporting the same
     * shared session id.
     */
    private static final class Node implements AutoCloseable {
        final MongoClient client;
        final MongoStatePoolStore store;
        final MockSessionStore sessionStore = new FixedSessionIdSessionStore();
        final MockWebContext webContext = MockWebContext.create();

        Node(final String databaseName) {
            this.client = MongoClients.create(mongo.getConnectionString());
            this.store = new MongoStatePoolStore(client.getDatabase(databaseName),
                MongoStatePoolStore.DEFAULT_STATE_COLLECTION,
                MongoStatePoolStore.DEFAULT_SECRETS_COLLECTION, false);
        }

        CallContext ctx() {
            return new CallContext(webContext, sessionStore);
        }

        @Override
        public void close() {
            client.close();
        }
    }

    /** MockSessionStore reporting the same session id for every node. */
    private static final class FixedSessionIdSessionStore extends MockSessionStore {
        @Override
        public Optional<String> getSessionId(final WebContext context, final boolean createSession) {
            return Optional.of(SHARED_SESSION_ID);
        }
    }

    private List<Node> newNodes(final int count) {
        final List<Node> nodes = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            nodes.add(new Node(database.getName()));
        }
        return nodes;
    }

    private static <T> List<T> race(final List<? extends Callable<T>> tasks) throws Exception {
        val pool = Executors.newFixedThreadPool(tasks.size());
        val barrier = new CyclicBarrier(tasks.size());
        final List<Future<T>> futures = tasks.stream()
            .map(task -> pool.submit(() -> {
                barrier.await(10, TimeUnit.SECONDS);
                return task.call();
            }))
            .collect(Collectors.toList());
        pool.shutdown();
        assertTrue("all racers finished", pool.awaitTermination(60, TimeUnit.SECONDS));
        final List<T> results = new ArrayList<>(tasks.size());
        for (final Future<T> future : futures) {
            results.add(future.get());
        }
        return results;
    }

    @Test
    public void concurrentStateConsumeYieldsExactlyOneWinnerAcrossNodes() throws Exception {
        val nodes = newNodes(RACERS);
        try {
            for (int round = 0; round < ROUNDS; round++) {
                final String stateValue = "hot-state-" + round;
                nodes.get(0).store.add(nodes.get(0).ctx(), CLIENT_NAME, stateValue,
                    TTL_MILLIS, MAX_SIZE);

                final List<Callable<Boolean>> tasks = nodes.stream()
                    .<Callable<Boolean>>map(node -> () -> node.store.consume(
                        node.ctx(), CLIENT_NAME, stateValue, TTL_MILLIS))
                    .collect(Collectors.toList());
                final List<Boolean> results = race(tasks);

                final long winners = results.stream().filter(Boolean::booleanValue).count();
                assertEquals("round " + round + ": exactly one of " + RACERS
                        + " concurrent nodes may consume the state",
                    1L, winners);
            }
        } finally {
            nodes.forEach(Node::close);
        }
    }

    @Test
    public void concurrentVerifierConsumeYieldsExactlyOneWinnerAcrossNodes() throws Exception {
        val nodes = newNodes(RACERS);
        try {
            nodes.get(0).store.add(nodes.get(0).ctx(), CLIENT_NAME, "v-state",
                TTL_MILLIS, MAX_SIZE);
            nodes.get(0).store.addFlowSecrets(nodes.get(0).ctx(), CLIENT_NAME, "v-state",
                "v-verifier", null, TTL_MILLIS, MAX_SIZE);

            final List<Callable<Optional<String>>> tasks = nodes.stream()
                .<Callable<Optional<String>>>map(node -> () -> node.store.consumeCodeVerifier(
                    node.ctx(), CLIENT_NAME, "v-state", TTL_MILLIS))
                .collect(Collectors.toList());
            final List<Optional<String>> results = race(tasks);

            final List<Optional<String>> winners = results.stream()
                .filter(Optional::isPresent).collect(Collectors.toList());
            assertEquals("exactly one node gets the verifier", 1, winners.size());
            assertEquals(Optional.of("v-verifier"), winners.get(0));
        } finally {
            nodes.forEach(Node::close);
        }
    }

    @Test
    public void concurrentNonceByValueConsumeYieldsExactlyOneWinnerAcrossNodes() throws Exception {
        val nodes = newNodes(RACERS);
        try {
            nodes.get(0).store.add(nodes.get(0).ctx(), CLIENT_NAME, "n-state",
                TTL_MILLIS, MAX_SIZE);
            nodes.get(0).store.addFlowSecrets(nodes.get(0).ctx(), CLIENT_NAME, "n-state",
                null, "n-nonce", TTL_MILLIS, MAX_SIZE);

            final List<Callable<Boolean>> tasks = nodes.stream()
                .<Callable<Boolean>>map(node -> () -> node.store.consumeNonceByValue(
                    node.ctx(), CLIENT_NAME, "n-nonce", TTL_MILLIS))
                .collect(Collectors.toList());
            final List<Boolean> results = race(tasks);

            final long winners = results.stream().filter(Boolean::booleanValue).count();
            assertEquals("exactly one node consumes the nonce by value", 1L, winners);
        } finally {
            nodes.forEach(Node::close);
        }
    }
}
