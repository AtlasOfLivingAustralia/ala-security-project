package au.org.ala.pac4j.oidc.statepool.mongo;

import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.FindOneAndUpdateOptions;
import com.mongodb.client.model.IndexOptions;
import com.mongodb.client.model.Indexes;
import com.mongodb.client.model.ReturnDocument;
import com.mongodb.client.model.Sorts;
import com.mongodb.client.model.UpdateOptions;
import com.mongodb.client.model.Updates;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.exception.TechnicalException;
import au.org.ala.pac4j.oidc.statepool.SessionStatePoolStore;
import au.org.ala.pac4j.oidc.statepool.StatePoolStore;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * MongoDB-backed {@link StatePoolStore} for non-sticky multi-node clusters, where
 * {@link SessionStatePoolStore} cannot guarantee atomicity.
 *
 * <p>Consumes are atomic single-document operations: {@code findOneAndDelete} for states,
 * {@code findOneAndUpdate} ({@code ReturnDocument.BEFORE} + {@code $unset}) for secrets.
 *
 * <p>Two collections decouple the state lifecycle from the secret lifecycle:
 * {@code oidc_state_pool} holds valid states and is consumed by {@link #consume};
 * {@code oidc_flow_secrets} holds {@code state → {codeVerifier, nonce}} and survives state
 * consumption so pac4j can retrieve the verifier and nonce on the callback.
 *
 * <p>Indexes are created idempotently by {@link #ensureIndexes()} (TTL, uniqueness, LRU sweep);
 * see the module README for the full listing.
 *
 * <p>{@code maxSize} is a best-effort, non-atomic post-write LRU sweep; the pool may briefly
 * exceed the bound under concurrency.
 *
 * <p>Writes throw {@link TechnicalException} on driver errors; consumes/checks fail closed
 * (empty/false). Null/blank inputs are rejected silently.
 *
 * @author pac4j state-pool contributors
 * @since 1.0.0
 */
public class MongoStatePoolStore implements StatePoolStore {

    /** Default collection name for the valid-states set. */
    public static final String DEFAULT_STATE_COLLECTION = "oidc_state_pool";
    /** Default collection name for the per-flow secret associations. */
    public static final String DEFAULT_SECRETS_COLLECTION = "oidc_flow_secrets";

    private static final String F_SESSION = "sessionId";
    private static final String F_CLIENT = "clientName";
    private static final String F_STATE = "state";
    private static final String F_VERIFIER = "codeVerifier";
    private static final String F_NONCE = "nonce";
    private static final String F_CREATED = "createdAt";
    private static final String F_EXPIRES = "expiresAt";

    private static final FindOneAndUpdateOptions RETURN_BEFORE =
        new FindOneAndUpdateOptions().returnDocument(ReturnDocument.BEFORE);
    private static final UpdateOptions UPSERT =
        new UpdateOptions().upsert(true);

    private final MongoCollection<Document> states;
    private final MongoCollection<Document> secrets;

    /**
     * @param database the Mongo database (must not be {@code null})
     */
    public MongoStatePoolStore(final MongoDatabase database) {
        this(database, DEFAULT_STATE_COLLECTION, DEFAULT_SECRETS_COLLECTION, true);
    }

    /**
     * @param database          the Mongo database (must not be {@code null})
     * @param stateCollection   valid-states collection
     * @param secretsCollection state → secrets collection
     */
    public MongoStatePoolStore(final MongoDatabase database, final String stateCollection,
                               final String secretsCollection) {
        this(database, stateCollection, secretsCollection, true);
    }

    /**
     * @param database          the Mongo database (must not be {@code null})
     * @param stateCollection   valid-states collection
     * @param secretsCollection state → secrets collection
     * @param createIndexes     whether to create the required indexes (see class javadoc)
     */
    public MongoStatePoolStore(final MongoDatabase database, final String stateCollection,
                               final String secretsCollection, final boolean createIndexes) {
        Objects.requireNonNull(database, "database must not be null");
        if (stateCollection == null || stateCollection.isBlank()) {
            throw new IllegalArgumentException("stateCollection cannot be blank");
        }
        if (secretsCollection == null || secretsCollection.isBlank()) {
            throw new IllegalArgumentException("secretsCollection cannot be blank");
        }
        this.states = database.getCollection(stateCollection);
        this.secrets = database.getCollection(secretsCollection);
        if (createIndexes) {
            ensureIndexes();
        }
    }

    /**
     * Create the required indexes. Idempotent.
     */
    public final void ensureIndexes() {
        final IndexOptions ttl = new IndexOptions().expireAfter(0L, TimeUnit.SECONDS);
        states.createIndex(Indexes.ascending(F_EXPIRES), ttl);
        secrets.createIndex(Indexes.ascending(F_EXPIRES), ttl);
        final IndexOptions unique = new IndexOptions().unique(true);
        states.createIndex(Indexes.ascending(F_SESSION, F_CLIENT, F_STATE), unique);
        secrets.createIndex(Indexes.ascending(F_SESSION, F_CLIENT, F_STATE), unique);
        states.createIndex(Indexes.ascending(F_SESSION, F_CLIENT, F_CREATED));
        secrets.createIndex(Indexes.ascending(F_SESSION, F_CLIENT, F_CREATED));
        secrets.createIndex(Indexes.ascending(F_SESSION, F_CLIENT, F_NONCE));
    }

    /** {@inheritDoc} */
    @Override
    public void add(final CallContext ctx, final String clientName, final String stateValue,
                    final long ttlMillis, final int maxSize) {
        if (stateValue == null || stateValue.isBlank()) {
            return;
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            // Re-add refreshes createdAt/expiresAt (LRU touch).
            states.updateOne(
                keyFilter(sessionId, clientName, F_STATE, stateValue),
                Updates.combine(
                    Updates.set(F_CREATED, Date.from(Instant.now())),
                    Updates.set(F_EXPIRES, expiryFromNow(ttlMillis))),
                UPSERT);
            evictOverflow(states, sessionId, clientName, maxSize);
        } catch (final RuntimeException e) {
            throw new TechnicalException("MongoStatePoolStore.add failed for client " + clientName, e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean consume(final CallContext ctx, final String clientName, final String stateValue,
                           final long ttlMillis) {
        if (stateValue == null || stateValue.isBlank()) {
            return false;
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            final Bson filter = Filters.and(
                keyFilter(sessionId, clientName, F_STATE, stateValue),
                Filters.gt(F_EXPIRES, Date.from(Instant.now())));
            return states.findOneAndDelete(filter) != null;
        } catch (final RuntimeException e) {
            return false;
        }
    }

    /** {@inheritDoc} */
    @Override
    public void addFlowSecrets(final CallContext ctx, final String clientName, final String stateValue,
                               final String codeVerifier, final String nonce,
                               final long ttlMillis, final int maxSize) {
        if (stateValue == null || stateValue.isBlank()) {
            return;
        }
        if (codeVerifier == null && nonce == null) {
            return;
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            final var sets = new ArrayList<Bson>(4);
            sets.add(Updates.set(F_CREATED, Date.from(Instant.now())));
            sets.add(Updates.set(F_EXPIRES, expiryFromNow(ttlMillis)));
            // null leaves the existing field untouched.
            if (codeVerifier != null) {
                sets.add(Updates.set(F_VERIFIER, codeVerifier));
            }
            if (nonce != null) {
                sets.add(Updates.set(F_NONCE, nonce));
            }
            secrets.updateOne(
                keyFilter(sessionId, clientName, F_STATE, stateValue),
                Updates.combine(sets),
                UPSERT);
            evictOverflow(secrets, sessionId, clientName, maxSize);
        } catch (final RuntimeException e) {
            throw new TechnicalException(
                "MongoStatePoolStore.addFlowSecrets failed for client " + clientName, e);
        }
    }

    /** {@inheritDoc} */
    @Override
    public Optional<String> consumeCodeVerifier(final CallContext ctx, final String clientName,
                                                final String stateValue, final long ttlMillis) {
        if (stateValue == null || stateValue.isBlank()) {
            return Optional.empty();
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            final Bson filter = Filters.and(
                keyFilter(sessionId, clientName, F_STATE, stateValue),
                Filters.exists(F_VERIFIER, true),
                Filters.gt(F_EXPIRES, Date.from(Instant.now())));
            final Document before = secrets.findOneAndUpdate(
                filter, Updates.unset(F_VERIFIER), RETURN_BEFORE);
            if (before == null) {
                return Optional.empty();
            }
            dropIfEmpty(before.getObjectId("_id"), before, F_VERIFIER);
            return Optional.ofNullable(before.getString(F_VERIFIER));
        } catch (final RuntimeException e) {
            return Optional.empty();
        }
    }

    /** {@inheritDoc} */
    @Override
    public Optional<String> consumeNonce(final CallContext ctx, final String clientName,
                                         final String stateValue, final long ttlMillis) {
        if (stateValue == null || stateValue.isBlank()) {
            return Optional.empty();
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            final Bson filter = Filters.and(
                keyFilter(sessionId, clientName, F_STATE, stateValue),
                Filters.exists(F_NONCE, true),
                Filters.gt(F_EXPIRES, Date.from(Instant.now())));
            final Document before = secrets.findOneAndUpdate(
                filter, Updates.unset(F_NONCE), RETURN_BEFORE);
            if (before == null) {
                return Optional.empty();
            }
            dropIfEmpty(before.getObjectId("_id"), before, F_NONCE);
            return Optional.ofNullable(before.getString(F_NONCE));
        } catch (final RuntimeException e) {
            return Optional.empty();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean containsNonce(final CallContext ctx, final String clientName,
                                 final String nonceValue, final long ttlMillis) {
        if (nonceValue == null || nonceValue.isBlank()) {
            return false;
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            final Bson filter = Filters.and(
                keyFilter(sessionId, clientName, F_NONCE, nonceValue),
                Filters.gt(F_EXPIRES, Date.from(Instant.now())));
            return secrets.find(filter).limit(1).first() != null;
        } catch (final RuntimeException e) {
            return false;
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean consumeNonceByValue(final CallContext ctx, final String clientName,
                                       final String nonceValue, final long ttlMillis) {
        if (nonceValue == null || nonceValue.isBlank()) {
            return false;
        }
        final String sessionId = resolveSessionId(ctx);
        try {
            final Bson filter = Filters.and(
                keyFilter(sessionId, clientName, F_NONCE, nonceValue),
                Filters.gt(F_EXPIRES, Date.from(Instant.now())));
            final Document before = secrets.findOneAndUpdate(
                filter, Updates.unset(F_NONCE), RETURN_BEFORE);
            if (before == null) {
                return false;
            }
            dropIfEmpty(before.getObjectId("_id"), before, F_NONCE);
            return true;
        } catch (final RuntimeException e) {
            return false;
        }
    }

    /**
     * Live state count for a client/session (diagnostics / tests).
     *
     * @param ctx        the current call context
     * @param clientName the OIDC client name
     * @return the live state count
     */
    public long stateCount(final CallContext ctx, final String clientName) {
        final String sessionId = resolveSessionId(ctx);
        return states.countDocuments(Filters.and(
            scopeFilter(sessionId, clientName),
            Filters.gt(F_EXPIRES, Date.from(Instant.now()))));
    }

    /**
     * Live secret-association count for a client/session (diagnostics / tests).
     *
     * @param ctx        the current call context
     * @param clientName the OIDC client name
     * @return the live association count
     */
    public long secretsCount(final CallContext ctx, final String clientName) {
        final String sessionId = resolveSessionId(ctx);
        return secrets.countDocuments(Filters.and(
            scopeFilter(sessionId, clientName),
            Filters.gt(F_EXPIRES, Date.from(Instant.now()))));
    }

    /* ------------------------------------------------------------------ */
    /* internals                                                          */
    /* ------------------------------------------------------------------ */

    /** Exact-key filter scoped to session + client. */
    private static Bson keyFilter(final String sessionId, final String clientName,
                                  final String field, final String value) {
        return Filters.and(scopeFilter(sessionId, clientName), Filters.eq(field, value));
    }

    /** Session + client namespace filter. */
    private static Bson scopeFilter(final String sessionId, final String clientName) {
        return Filters.and(Filters.eq(F_SESSION, sessionId), Filters.eq(F_CLIENT, clientName));
    }

    private static Date expiryFromNow(final long ttlMillis) {
        return Date.from(Instant.now().plusMillis(ttlMillis));
    }

    /**
     * Best-effort LRU sweep: delete oldest by {@code createdAt} while over {@code maxSize}.
     * Non-atomic; the pool may briefly exceed the bound under concurrency.
     */
    private void evictOverflow(final MongoCollection<Document> collection, final String sessionId,
                               final String clientName, final int maxSize) {
        if (maxSize <= 0) {
            return;
        }
        final Bson liveScope = Filters.and(
            scopeFilter(sessionId, clientName),
            Filters.gt(F_EXPIRES, Date.from(Instant.now())));
        while (collection.countDocuments(liveScope) > maxSize) {
            final Document eldest = collection.find(liveScope)
                .sort(Sorts.ascending(F_CREATED))
                .limit(1)
                .first();
            if (eldest == null) {
                return;
            }
            collection.deleteOne(Filters.eq("_id", eldest.getObjectId("_id")));
        }
    }

    /**
     * Delete a secrets document once both secret fields are gone. Guarded on both fields still
     * being absent so a concurrent re-add of the sibling secret cannot lose data.
     *
     * @param id            the {@code _id} of the consumed document
     * @param before        the BEFORE image returned by the atomic consume
     * @param consumedField the field the caller just unset ({@code codeVerifier} or {@code nonce})
     */
    private void dropIfEmpty(final Object id, final Document before, final String consumedField) {
        final String otherField = F_VERIFIER.equals(consumedField) ? F_NONCE : F_VERIFIER;
        if (before.getString(otherField) != null) {
            return;
        }
        secrets.deleteOne(Filters.and(
            Filters.eq("_id", id),
            Filters.exists(F_VERIFIER, false),
            Filters.exists(F_NONCE, false)));
    }

    /**
     * Resolve the session id from the {@link SessionStore} without creating a session
     * ({@code createSession=false}). Falls back to the session store identity when no session
     * exists yet.
     */
    private String resolveSessionId(final CallContext ctx) {
        final WebContext webContext = ctx.webContext();
        final SessionStore sessionStore = ctx.sessionStore();
        if (webContext != null && sessionStore != null) {
            final Optional<String> id = sessionStore.getSessionId(webContext, false);
            if (id.isPresent() && !id.get().isBlank()) {
                return id.get();
            }
        }
        return "session-store@" + Integer.toHexString(System.identityHashCode(sessionStore));
    }
}
