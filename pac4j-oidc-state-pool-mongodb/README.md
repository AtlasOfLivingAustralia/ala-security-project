# pac4j-oidc-state-pool-mongodb

Multi-node-safe MongoDB-backed
[`StatePoolStore`](../pac4j-oidc-state-pool/README.md) for
`pac4j-oidc-state-pool`. Use this when callbacks can land on a different node than the login
(non-sticky load balancing), where the default in-session store cannot guarantee atomic
find-and-remove.

Every consume is a single-document atomic operation executed by the MongoDB server:

- `consume(state)` → `findOneAndDelete({sessionId, clientName, state, expiresAt: {$gt: now}})`
- `consumeCodeVerifier` / `consumeNonce` / `consumeNonceByValue` →
  `findOneAndUpdate(..., {$unset: {field}}, ReturnDocument.BEFORE)`; the value is read back from
  the BEFORE image and exactly one caller observes it.

Single-document operations are atomic even on a standalone node — no replica set, multi-document
transaction, or client-side lock required.

## Dependency

```xml
<dependency>
    <groupId>au.org.ala</groupId>
    <artifactId>pac4j-oidc-state-pool-mongodb</artifactId>
    <version>7.2.0-SNAPSHOT</version>
</dependency>
```

`org.mongodb:mongodb-driver-sync` is a compile dependency and arrives transitively, as does
pac4j 6.3.x via the base library. The driver is tested and pinned against MongoDB driver sync
**4.7.1**; other versions may work but are untested — override at your own risk.

Build from the repository root; Gradle resolves the base module as an in-repository project
dependency:

```bash
./gradlew :pac4j-oidc-state-pool-mongodb:build
```

## Wiring

```java
import au.org.ala.pac4j.oidc.statepool.StatePoolOidcClient;
import au.org.ala.pac4j.oidc.statepool.mongo.MongoStatePoolStore;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoDatabase;

MongoDatabase db = MongoClients.create("mongodb://mongo.internal:27017").getDatabase("myapp");
MongoStatePoolStore store = new MongoStatePoolStore(db);   // creates collections + indexes

StatePoolOidcClient client = new StatePoolOidcClient(config,
        Duration.ofMinutes(5).toMillis(), 20);
client.setStatePoolStore(store);                 // or pass to the constructor
client.setCallbackUrl("https://app.example.com/callback");
```

Pools are namespaced per user session: the store resolves the session id from
`ctx.sessionStore().getSessionId(webContext, false)` — the same derivation as the default store —
so every node keys the same session identically and two sessions never share entries.

**Cluster requirement — session must exist before OIDC initiation.** `resolveSessionId` calls
`getSessionId(webContext, false)`: it never creates a session. If no session id is present, the
store falls back to a process-local identifier (`session-store@<identityHashCode>`) that is only
valid within that JVM — two nodes derive *different* keys for the same logical user, so a
callback landing on a different node than the login would find no state. In a multi-node
cluster, a stable HTTP session (and therefore a session id) must already be established prior to
OIDC initiation; ensure your entry point creates the session before the redirect to the OP.

## Data model

The base library's decoupled lifecycle (a `state` is consumed before its verifier/nonce are
needed) maps onto two collections:

| Collection | Document | Role |
|---|---|---|
| `oidc_state_pool` | `{sessionId, clientName, state, createdAt, expiresAt}` | Valid-states set; `consume` deletes here. |
| `oidc_flow_secrets` | `{sessionId, clientName, state, codeVerifier?, nonce?, createdAt, expiresAt}` | `state → secrets` associations. Untouched by `consume(state)` so the later authenticator/profile-creator stages still find the secrets. Secret consumes `$unset` their own field; the document is dropped once empty. |

Both names are constructor-configurable: `new MongoStatePoolStore(db, "my_states", "my_secrets")`.

## Indexes

Created idempotently by the constructor (call `ensureIndexes()` yourself, or pass
`createIndexes=false` to the three-arg constructor to manage them out-of-band):

```java
// TTL: server reaps expired docs (expireAfterSeconds: 0)
states.createIndex(Indexes.ascending("expiresAt"),  new IndexOptions().expireAfter(0L, SECONDS));
secrets.createIndex(Indexes.ascending("expiresAt"), new IndexOptions().expireAfter(0L, SECONDS));
// uniqueness + exact-key consume lookup
states.createIndex(Indexes.ascending("sessionId", "clientName", "state"),  new IndexOptions().unique(true));
secrets.createIndex(Indexes.ascending("sessionId", "clientName", "state"), new IndexOptions().unique(true));
// LRU sweep (count + delete-oldest by createdAt)
states.createIndex(Indexes.ascending("sessionId", "clientName", "createdAt"));
secrets.createIndex(Indexes.ascending("sessionId", "clientName", "createdAt"));
// nonce-by-value lookup
secrets.createIndex(Indexes.ascending("sessionId", "clientName", "nonce"));
```

## Operational constraints

- **TTL lag:** the TTL monitor runs roughly every 60 s, so every read/consume filter also carries
  `expiresAt: {$gt: now}` — expired-but-not-yet-reaped documents are treated as absent. The
  monitor is never relied on for correctness.
- **Approximate `maxSize`:** the LRU bound is a best-effort, non-atomic post-write sweep (count
  live docs, delete oldest by `createdAt`). Under concurrency the pool may briefly exceed
  `maxSize`; acceptable because the bound is a capacity guard, not a security check — the
  security-critical `consume` is fully atomic.
- **Fail closed:** null/blank state/verifier/nonce inputs are no-ops (writes) or empty/false
  (reads). A driver error on a write surfaces as a pac4j `TechnicalException`; on a consume/check
  it surfaces as empty/false — "could not prove validity" never validates.

## Tests

`src/test/java/au/org/ala/pac4j/oidc/statepool/mongo/` runs against a real MongoDB via
Testcontainers (`mongo:6.0.26`, single node — single-document atomicity needs no replica set).
Requires a working Docker daemon.

```
au/org/ala/pac4j/oidc/statepool/mongo/
└── MongoStatePoolStore.java
```
