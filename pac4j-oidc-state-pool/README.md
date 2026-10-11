# pac4j OIDC State Pool

Concurrent OIDC `state` (and optionally PKCE `code_verifier` / `nonce`) tracking for pac4j 6.3.x.
pac4j's stock `OidcClient` stores exactly one `state` per session, so a second concurrent login
clobbers the first. This extension replaces the single slot with a bounded pool of valid states,
each one-time-use.

- **Coordinates:** `au.org.ala : pac4j-oidc-state-pool`
- **Package:** `au.org.ala.pac4j.oidc.statepool`
- **pac4j version:** 6.3.x (built against 6.3.3) — see [Upstream coupling](#upstream-coupling).
- **License:** Apache-2.0, matching pac4j. Maintainer: [Atlas of Living Australia](https://www.ala.org.au).

### Dependency

```xml
<dependency>
    <groupId>au.org.ala</groupId>
    <artifactId>pac4j-oidc-state-pool</artifactId>
    <version>7.2.0-SNAPSHOT</version>
</dependency>
```

```groovy
implementation 'au.org.ala:pac4j-oidc-state-pool:7.2.0-SNAPSHOT'
```

## Architecture

| Class | Role |
|-------|------|
| `StatePoolStore` | SPI. `add(...)` persists a state; `consume(...)` is an atomic find-and-remove. Flow-secret operations (`addFlowSecrets`, `consumeCodeVerifier`, `consumeNonce`, `consumeNonceByValue`, `containsNonce`) are default methods, so existing v1 stores keep compiling and simply disable PKCE/nonce pooling. |
| `SessionStatePoolStore` | Default store. Holds the pool and flow-secret associations in the pac4j `SessionStore` as a single `StatePoolHolder`; atomic within a JVM via a static 1024-stripe `ReentrantLock` table keyed by session id. |
| `StatePoolHolder` | The `Serializable` session payload: two insertion-ordered maps, `state → createdAt` and `state → FlowSecrets`. The only type placed in the session; survives serialization-based session stores. |
| `FlowSecrets` | One flow's PKCE `code_verifier` and/or `nonce` plus insertion timestamp. |
| `StatePool` | Stateless helper carrying only TTL/bound config; every method takes `(ctx, clientName)`. Share one instance across clients and the JVM. |
| `StatePoolValueRetriever` | `ValueRetriever` that dispatches on the requested key. `state` key: reads the request's `state` parameter, consumes the matching pool entry, returns it so pac4j's equality check passes; fails closed to `Optional.empty()` on any inconsistency. `code_verifier` key: serves the pooled verifier keyed by the echoed `state` (one-time use), failing closed when a `state` is present but its association is gone; falls back to the raw session slot only when the request carries no `state` parameter (`withState=false`). Any other key: plain session-store read, unconsumed. |
| `StatePoolOidcRedirectionActionBuilder` | Subclass of `OidcRedirectionActionBuilder`; after the stock single-slot write, also records the generated `state` (and, when enabled, its verifier and nonce) into the pool. |
| `StatePoolOidcProfileCreator` | `ProfileCreator` decorator installed when nonce pooling is enabled. It selects and consumes the expected nonce from the pool, then delegates with a request-local `SessionStore` view that overrides only the nonce read. The real session is not mutated. |
| `StatePoolOidcClient` | Convenience `OidcClient` wiring all components to a shared `StatePool`. It decorates a caller-configured profile creator when present, otherwise pac4j's stock `OidcProfileCreator`. Exposes `setPkcePoolingEnabled(boolean)` (default true) and `setNoncePoolingEnabled(boolean)` (default false). |

### Lifecycle contract

pac4j's callback pipeline runs `OidcCredentialsExtractor` (consumes `state`) → `OidcAuthenticator`
(retrieves `code_verifier`) → `OidcProfileCreator` (validates `nonce`). State consumption is
therefore decoupled from the flow secrets: the `state → FlowSecrets` association **survives**
`consume(state)` and is consumed independently by the later stages. Each secret is one-time-use;
an entry is dropped once empty. Abandoned associations age out via TTL and LRU eviction.

The retriever correlates the current callback to a pool entry via the `state` request parameter
(query string and `form_post` are both surfaced as request parameters). If your `WebContext` does
not expose parameters, configure a `fallbackRequestAttributeName` and populate it before the
extractor runs.

### Pool semantics

- **One-time use** per state and per secret. pac4j calls the retriever once per callback; a
  pipeline invoking the extractor twice for one callback fails on the second pass by design.
- **TTL:** entries older than `ttlMillis` are swept on access and rejected. Default 5 minutes.
- **Bounded LRU:** insertion-ordered map with explicit remove-then-reinsert on `add`; eldest
  entries evicted past `maxSize`. Default 20. Size for peak concurrent logins per session.
- **Namespacing:** pool key is `<clientName>$statePool` (per-client), stored in the current
  session (per-session isolation).
- **Fail closed:** a request with a `state` parameter but no live association gets
  `Optional.empty()`, never the shared single slot.

## Deployment topologies

Correctness requires `consume` to be an atomic find-and-remove.

- **`SessionStatePoolStore` (default):** atomic within one JVM via the stripe-lock table. Correct
  for single-node deployments and sticky-session clusters. The holder is `Serializable`, so it
  round-trips through serialization-based session stores (e.g. Spring Session + Redis) — but that
  only guarantees object survival, not cross-node read-modify-write atomicity.
- **Non-sticky / replicated clusters:** in-JVM locking degenerates to last-writer-wins and a
  `state` can be consumed twice. Plug in a `StatePoolStore` with a native atomic
  compare-and-delete — e.g. the sibling artifact
  [`pac4j-oidc-state-pool-mongodb`](../pac4j-oidc-state-pool-mongodb/README.md), an explicitly
  atomic Redis compare-and-delete (a Lua script that checks the value before `DEL`, or `GETDEL`
  with a key-per-state structure), or SQL `DELETE ... WHERE state=?` with row-count check.

```java
public interface StatePoolStore {
    void add(CallContext ctx, String clientName, String stateValue, long ttlMillis, int maxSize);
    /** MUST be an atomic find-and-remove: true for exactly one concurrent caller per state. */
    boolean consume(CallContext ctx, String clientName, String stateValue, long ttlMillis);
}
```

The SPI methods take only `CallContext`, `clientName`, `stateValue`, and `ttlMillis`/`maxSize` —
no backing-store types leak into the interface.

## Feature flags

- **PKCE pooling** (`setPkcePoolingEnabled`) — **on by default**. The verifier is not echoed on
  the callback, so the redirect records `state → code_verifier` and the retriever recovers it for
  the echoed state, one-time use. Disable to keep the stock single-slot behaviour.
- **Nonce pooling** (`setNoncePoolingEnabled`) — **opt-in, off by default**. pac4j validates the
  nonce by reading the session slot directly (bypassing the retriever), so pooling requires the
  `StatePoolOidcProfileCreator`, which the client installs when the pooling flag is set. Pool
  resolution applies when `config.setUseNonce(true)` is also set and is skipped for refreshed
  credentials when `useNonceOnRefresh` is false. For the code+PKCE flow the nonce is redundant;
  enable only for concurrent nonce-bearing flows (implicit/hybrid). The claimed nonce selects and
  consumes the pooled entry, then the configured profile creator performs its normal validation
  through a request-local nonce view. Nimbus still performs full signature and claim validation;
  an unknown, expired, or consumed nonce fails closed with `OidcException`.

## Upstream coupling

Pinned to **pac4j 6.3.x** (built against 6.3.3). One internal override remains version-coupled:

`StatePoolOidcRedirectionActionBuilder` overrides the protected internal
`OidcRedirectionActionBuilder#addStateAndNonceParameters(CallContext, Map<String,String>)` —
the only hook to populate the pool on redirect. In pac4j 6.4.0 the second parameter changed to
`Params`, breaking the override at compile time and at run time (`NoSuchMethodError`).

`StatePoolOidcProfileCreator` no longer copies pac4j's profile creation flow; it uses the public
`ProfileCreator`, `CallContext`, and `SessionStore` contracts and delegates all profile work.

Do not raise the pac4j version past 6.3.x without re-checking the redirect-builder override and
the public composition contracts.

## Usage

```java
OidcConfiguration config = new OidcConfiguration();
config.setClientId("...");
config.setSecret("...");
config.setDiscoveryURI("https://op.example.com/.well-known/openid-configuration");

// Option A: convenience client
StatePoolOidcClient client = new StatePoolOidcClient(
        config,
        Duration.ofMinutes(5).toMillis(),  // state TTL
        20);                               // max concurrent states per session
client.setCallbackUrl("https://app.example.com/callback");
client.setPkcePoolingEnabled(true);        // default true
client.setNoncePoolingEnabled(true);       // default false; requires config.setUseNonce(true)
```

```java
// Option B: manual wiring
StatePool pool = new StatePool(new SessionStatePoolStore(), ttlMillis, maxSize);
config.setValueRetriever(new StatePoolValueRetriever(pool, null, /*pkcePooling*/ true));
client.setRedirectionActionBuilder(
    new StatePoolOidcRedirectionActionBuilder(client, pool, /*pkcePooling*/ true, /*noncePooling*/ false));
// Nonce pooling additionally:
ProfileCreator delegate = new OidcProfileCreator(config, client); // or a custom creator
client.setProfileCreator(
    new StatePoolOidcProfileCreator(config, client, pool, true, delegate));
```

`StatePoolOidcProfileCreator` implements `ProfileCreator`; it is no longer an
`OidcProfileCreator` subtype. Existing calls to its four-argument constructor remain supported and
create a stock OIDC delegate, but code relying on `OidcProfileCreator` assignability must use the
`ProfileCreator` contract instead. `StatePoolOidcClient` automatically preserves and decorates a
profile creator configured before client initialization.

```java
// Custom store
StatePoolOidcClient client = new StatePoolOidcClient(config, myStore, ttlMillis, maxSize);
```

Package `au.org.ala.pac4j.oidc.statepool`:

```
StatePoolStore.java                           (SPI)
SessionStatePoolStore.java                    (default store)
StatePoolHolder.java                          (Serializable session payload)
FlowSecrets.java                              (per-flow verifier / nonce)
StatePool.java                                (stateless helper)
StatePoolValueRetriever.java                  (callback side)
StatePoolOidcRedirectionActionBuilder.java    (redirect side)
StatePoolOidcProfileCreator.java              (nonce pooling)
StatePoolOidcClient.java                      (convenience wiring)
```
