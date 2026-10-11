package au.org.ala.pac4j.oidc.statepool;

import lombok.val;
import org.junit.Test;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.MockWebContext;
import org.pac4j.core.context.session.MockSessionStore;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Serialization round-trip tests for {@link StatePoolHolder}: entries, timestamps, insertion
 * (LRU) order and the {@code consume} one-time-use contract must survive an externalizing
 * session store (Spring Session + Redis, or any Java-serialization-based store).
 */
public final class StatePoolHolderSerializationTest {

    private static final String CLIENT_NAME = "testClient";
    private static final long TTL_MILLIS = 5L * 60L * 1000L;
    private static final int MAX_SIZE = 20;

    private static StatePoolHolder roundTrip(final StatePoolHolder holder) throws Exception {
        val bytes = new ByteArrayOutputStream();
        try (val out = new ObjectOutputStream(bytes)) {
            out.writeObject(holder);
        }
        try (val in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return (StatePoolHolder) in.readObject();
        }
    }

    /**
     * Entries — values AND their insertion timestamps — survive a round-trip exactly, including
     * insertion order (which drives LRU eviction).
     */
    @Test
    public void entriesAndTimestampsSurviveRoundTrip() throws Exception {
        val entries = new LinkedHashMap<String, Long>();
        entries.put("state-a", 1_000L);
        entries.put("state-b", 2_000L);
        entries.put("state-c", 3_000L);

        val restored = roundTrip(new StatePoolHolder(entries));

        assertEquals("all entries + timestamps must survive the round-trip",
            entries, restored.getEntries());
        // LinkedHashMap equality does not check order; assert iteration order explicitly.
        assertEquals("insertion order must survive the round-trip",
            entries.keySet().stream().toList(),
            restored.getEntries().keySet().stream().toList());
    }

    /**
     * A {@code consume} against the deserialized holder (placed back in a session store) still
     * finds-and-removes the state and enforces one-time use, and the TTL sweep still applies.
     */
    @Test
    public void consumeOnDeserializedHolderStillEnforcesOneTimeUse() throws Exception {
        val store = new SessionStatePoolStore();
        val sessionStore = new MockSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        // Build a pool with several states through the normal write path, then round-trip the
        // holder that landed in the session and put the DESERIALIZED copy back.
        store.add(ctx, CLIENT_NAME, "s1", TTL_MILLIS, MAX_SIZE);
        store.add(ctx, CLIENT_NAME, "s2", TTL_MILLIS, MAX_SIZE);
        store.add(ctx, CLIENT_NAME, "s3", TTL_MILLIS, MAX_SIZE);

        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);
        val original = (StatePoolHolder) sessionStore.get(ctx.webContext(), key).orElseThrow();
        val restored = roundTrip(original);
        sessionStore.set(ctx.webContext(), key, restored);

        // Every entry survives and each can be consumed exactly once from the deserialized copy.
        for (val state : new String[] {"s1", "s2", "s3"}) {
            assertTrue("deserialized holder must still contain " + state,
                store.consume(ctx, CLIENT_NAME, state, TTL_MILLIS));
            assertFalse("one-time use must still hold after round-trip for " + state,
                store.consume(ctx, CLIENT_NAME, state, TTL_MILLIS));
        }

        // TTL sweep still applies on the deserialized holder.
        store.add(ctx, CLIENT_NAME, "fresh", TTL_MILLIS, MAX_SIZE);
        assertTrue(store.consume(ctx, CLIENT_NAME, "fresh", TTL_MILLIS));

        val staleEntries = new LinkedHashMap<String, Long>();
        staleEntries.put("stale", System.currentTimeMillis() - (TTL_MILLIS + 1_000L));
        sessionStore.set(ctx.webContext(), key, roundTrip(new StatePoolHolder(staleEntries)));
        assertFalse("expired entries are still swept after a round-trip",
            store.consume(ctx, CLIENT_NAME, "stale", TTL_MILLIS));
    }

    /**
     * After a round-trip, adding one entry beyond {@code maxSize} evicts the eldest entry per
     * the insertion order that survived serialization.
     */
    @Test
    public void lruEvictionOrderSurvivesRoundTrip() throws Exception {
        val store = new SessionStatePoolStore();
        val sessionStore = new MockSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);

        // Insert in a known order, then round-trip the holder so its insertion order is the
        // serialized one.
        store.add(ctx, CLIENT_NAME, "eldest", TTL_MILLIS, 2);
        store.add(ctx, CLIENT_NAME, "middle", TTL_MILLIS, 2);

        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);
        val restored = roundTrip((StatePoolHolder) sessionStore.get(ctx.webContext(), key).orElseThrow());
        sessionStore.set(ctx.webContext(), key, restored);

        // Exceed maxSize=2: the eldest entry (by the order that survived serialization) is evicted.
        store.add(ctx, CLIENT_NAME, "newest", TTL_MILLIS, 2);

        assertFalse("eldest entry must be evicted by LRU after the round-trip",
            store.consume(ctx, CLIENT_NAME, "eldest", TTL_MILLIS));
        assertTrue(store.consume(ctx, CLIENT_NAME, "middle", TTL_MILLIS));
        assertTrue(store.consume(ctx, CLIENT_NAME, "newest", TTL_MILLIS));
    }

    /**
     * Member audit: every non-static, non-synthetic field on {@link StatePoolHolder} is
     * assignable to {@link Serializable}, and a {@code serialVersionUID} is present.
     */
    @Test
    public void holderContainsOnlySerializableMembers() {
        try {
            final Field svnField = StatePoolHolder.class.getDeclaredField("serialVersionUID");
            assertTrue("serialVersionUID must be static", Modifier.isStatic(svnField.getModifiers()));
            assertTrue("serialVersionUID must be final", Modifier.isFinal(svnField.getModifiers()));
            assertEquals("serialVersionUID must be a long", long.class, svnField.getType());
        } catch (NoSuchFieldException e) {
            fail("StatePoolHolder must declare a serialVersionUID field");
        }

        for (final Field field : StatePoolHolder.class.getDeclaredFields()) {
            if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
                continue;
            }
            assertTrue(
                "field '" + field.getName() + "' of type " + field.getType().getName()
                    + " must be assignable to java.io.Serializable",
                Serializable.class.isAssignableFrom(field.getType()));
        }
    }

    /**
     * A v1-shaped holder (entries only, no {@code flowSecrets}) deserializes cleanly and
     * {@code getFlowSecrets()} upgrades the {@code null} field to an empty, usable map.
     */
    @Test
    public void oldHolderWithoutFlowSecretsFieldDeserializesAndUpgrades() throws Exception {
        val entries = new LinkedHashMap<String, Long>();
        entries.put("state-old", 1_000L);
        val restored = roundTrip(new StatePoolHolder(entries));

        assertEquals("pool entries must survive", entries, restored.getEntries());
        assertTrue("flowSecrets must come back empty (not null) for an old holder",
            restored.getFlowSecrets().isEmpty());

        // The upgraded holder accepts new associations through the normal store write path.
        val store = new SessionStatePoolStore();
        val sessionStore = new MockSessionStore();
        val ctx = new CallContext(MockWebContext.create(), sessionStore);
        val key = SessionStatePoolStore.sessionKeyFor(CLIENT_NAME);
        sessionStore.set(ctx.webContext(), key, restored);

        store.add(ctx, CLIENT_NAME, "state-new", TTL_MILLIS, MAX_SIZE);
        store.addFlowSecrets(ctx, CLIENT_NAME, "state-new", "v-new", null, TTL_MILLIS, MAX_SIZE);
        assertEquals("an association can be added to a deserialized old holder",
            Optional.of("v-new"),
            store.consumeCodeVerifier(ctx, CLIENT_NAME, "state-new", TTL_MILLIS));
    }

    /**
     * {@code FlowSecrets} itself round-trips: verifier, nonce and timestamp survive, and the
     * one-time-use {@code isEmpty()} contract holds after deserialization.
     */
    @Test
    public void flowSecretsSurviveRoundTrip() throws Exception {
        val secrets = new FlowSecrets("verifier-abc", "nonce-xyz", 4_200L);
        val bytes = new ByteArrayOutputStream();
        try (val out = new ObjectOutputStream(bytes)) {
            out.writeObject(secrets);
        }
        final FlowSecrets restored;
        try (val in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            restored = (FlowSecrets) in.readObject();
        }
        assertEquals("verifier-abc", restored.getCodeVerifier());
        assertEquals("nonce-xyz", restored.getNonce());
        assertEquals(4_200L, restored.getCreatedAt());
        assertFalse(restored.isEmpty());
    }
}
