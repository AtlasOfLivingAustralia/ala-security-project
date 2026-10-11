package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.util.ValueRetriever;

import java.util.Objects;
import java.util.Optional;

/**
 * A {@link ValueRetriever} that validates against the OIDC {@code state} pool and recovers the
 * per-flow PKCE {@code code_verifier} associated with the echoed state.
 *
 * <p>The {@link ValueRetriever} signature does not receive the response state, so the current
 * request's {@code state} parameter ({@value #STATE_PARAM}) is read directly from the
 * {@link WebContext} to select the pool entry. The PKCE verifier is likewise keyed by the echoed
 * state (only {@code code} and {@code state} are echoed on the callback).</p>
 *
 * <p>Dispatch on {@code key}:</p>
 * <ol>
 *   <li><b>state key</b>: consume the pool entry matching the echoed state (one-time use) and
 *       return it. Any inconsistency — no parameter, unknown/expired/used state, blank client
 *       name — returns {@link Optional#empty()} so pac4j raises its normal error.</li>
 *   <li><b>PKCE code-verifier key</b>, when PKCE pooling is enabled: consume the verifier
 *       associated with the echoed state. Fail-closed: a request WITH a {@code state} parameter
 *       but no usable pooled association returns {@link Optional#empty()} — the raw single slot
 *       may hold a different flow's verifier. A request with NO {@code state} parameter
 *       ({@code withState=false}) falls back to the raw session slot.</li>
 *   <li><b>Any other key</b>: plain session-store read (stock pac4j behaviour).</li>
 * </ol>
 *
 * <p>If the response {@code state} is not a request parameter, an optional request-attribute
 * fallback can be configured.</p>
 */
@Slf4j
public class StatePoolValueRetriever implements ValueRetriever {

    /** The OIDC request/response parameter carrying the state value. */
    public static final String STATE_PARAM = "state";

    private final StatePool statePool;
    private final String fallbackRequestAttributeName;
    private final boolean pkcePoolingEnabled;

    /**
     * Create a retriever reading the response state from the {@value #STATE_PARAM} request
     * parameter, with PKCE pooling ON (the library default).
     */
    public StatePoolValueRetriever(final StatePool statePool) {
        this(statePool, null, true);
    }

    /**
     * Create a retriever with PKCE pooling ON (the library default).
     *
     * @param fallbackRequestAttributeName optional request attribute consulted when the
     *                                     {@value #STATE_PARAM} request parameter is absent
     *                                     ({@code null} disables the fallback)
     */
    public StatePoolValueRetriever(final StatePool statePool, final String fallbackRequestAttributeName) {
        this(statePool, fallbackRequestAttributeName, true);
    }

    /**
     * Create a retriever.
     *
     * @param fallbackRequestAttributeName optional request attribute consulted when the
     *                                     {@value #STATE_PARAM} request parameter is absent
     *                                     ({@code null} disables the fallback)
     * @param pkcePoolingEnabled           whether the PKCE code-verifier key is served from the
     *                                     state-keyed association map ({@code false} = always the
     *                                     raw session-slot fallback)
     */
    public StatePoolValueRetriever(final StatePool statePool, final String fallbackRequestAttributeName,
                                   final boolean pkcePoolingEnabled) {
        this.statePool = Objects.requireNonNull(statePool, "statePool must not be null");
        this.fallbackRequestAttributeName = fallbackRequestAttributeName;
        this.pkcePoolingEnabled = pkcePoolingEnabled;
    }

    /**
     * {@inheritDoc}
     *
     * <p>Dispatch on {@code key}: only the {@code state} key goes through the pool; the PKCE
     * verifier key is served from the state-keyed association map when pooling is enabled
     * (fail-closed when a state is present but its association is gone; raw session slot only
     * when the request carries no state at all); every other key falls back to a plain
     * session-store read.</p>
     */
    @Override
    public Optional<Object> retrieve(final CallContext ctx, final String key, final OidcClient client) {
        if (ctx == null || client == null) {
            return Optional.empty();
        }

        if (isStateKey(key, client)) {
            return retrieveState(ctx, client);
        }

        if (pkcePoolingEnabled && isCodeVerifierKey(key, client)) {
            return retrieveCodeVerifier(ctx, key, client);
        }

        // Nonce slot and any other non-state attribute: stock pac4j behaviour.
        return ctx.sessionStore().get(ctx.webContext(), key);
    }

    /**
     * The state branch: consume the pool entry matching the echoed {@code state} and return it.
     * Fails closed.
     */
    private Optional<Object> retrieveState(final CallContext ctx, final OidcClient client) {
        val webContext = ctx.webContext();

        val responseStateValue = resolveResponseStateValue(webContext);
        if (responseStateValue.isEmpty()) {
            log.debug("No response state on the current request; cannot select a pool entry");
            return Optional.empty();
        }

        // getName() self-initialises (falls back to the simple class name) and the client is
        // init()ed by the time pac4j reaches the extractor, so this matches the namespace the
        // redirect side used.
        val clientName = client.getName();
        if (clientName == null || clientName.isBlank()) {
            return Optional.empty();
        }

        val stateValue = responseStateValue.get();
        if (!statePool.consume(ctx, clientName, stateValue)) {
            log.debug("State not present in the pool (unknown, expired or already used)");
            return Optional.empty();
        }

        log.debug("State consumed from the pool; returning it for validation");
        return Optional.of(new State(stateValue));
    }

    /**
     * The PKCE verifier branch: consume the verifier associated with the echoed {@code state}.
     *
     * <p>Fail closed when a state IS present: the pooled path owns the correlation, so an absent
     * association returns empty rather than the shared single-slot value (which under concurrent
     * logins holds a different flow's verifier). The raw session-slot fallback applies only when
     * the request has NO {@code state} parameter ({@code withState=false}).</p>
     */
    private Optional<Object> retrieveCodeVerifier(final CallContext ctx, final String key,
                                                  final OidcClient client) {
        val responseStateValue = resolveResponseStateValue(ctx.webContext());

        // Stateless path (withState=false): serve the raw session slot as stock pac4j does.
        if (responseStateValue.isEmpty()) {
            log.debug("No state parameter on the request; using the raw session slot (withState=false path)");
            return ctx.sessionStore().get(ctx.webContext(), key);
        }

        val clientName = client.getName();
        if (clientName != null && !clientName.isBlank()) {
            val pooled = statePool.consumeCodeVerifier(ctx, clientName, responseStateValue.get());
            if (pooled.isPresent()) {
                log.debug("Returning pooled PKCE code_verifier for the echoed state");
                return Optional.of(new CodeVerifier(pooled.get()));
            }
        }

        // Present state but no usable pooled verifier: fail closed.
        log.debug("State present but no pooled verifier for it; failing closed (no session-slot fallback)");
        return Optional.empty();
    }

    /** Computed from the live client so the dispatch stays correct however pac4j builds the name. */
    private static boolean isStateKey(final String key, final OidcClient client) {
        return key != null && key.equals(client.getStateSessionAttributeName());
    }

    /** As {@link #isStateKey}, for the PKCE code-verifier session attribute. */
    private static boolean isCodeVerifierKey(final String key, final OidcClient client) {
        return key != null && key.equals(client.getCodeVerifierSessionAttributeName());
    }

    private Optional<String> resolveResponseStateValue(final WebContext webContext) {
        if (webContext == null) {
            return Optional.empty();
        }
        val fromParameter = webContext.getRequestParameter(STATE_PARAM);
        if (fromParameter.isPresent()) {
            return fromParameter;
        }
        if (fallbackRequestAttributeName == null) {
            return Optional.empty();
        }
        return webContext.getRequestAttribute(fallbackRequestAttributeName, String.class);
    }
}
