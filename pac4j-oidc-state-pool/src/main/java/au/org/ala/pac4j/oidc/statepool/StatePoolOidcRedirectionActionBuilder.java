package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import lombok.val;
import org.pac4j.core.context.CallContext;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.redirect.OidcRedirectionActionBuilder;

import java.util.Map;
import java.util.Objects;

/**
 * An {@link OidcRedirectionActionBuilder} that, in addition to pac4j's default single-slot
 * storage, records every generated state into the {@link StatePool} — and, when enabled, the
 * per-flow PKCE {@code code_verifier} and {@code nonce} keyed by that state.
 *
 * <p>{@code client.init()} is forced before the name is read (idempotent) so the pool key is
 * deterministic even when this builder is invoked directly, bypassing
 * {@code IndirectClient.getRedirectionAction}.</p>
 *
 * <p>Overrides the pac4j-internal {@code addStateAndNonceParameters(CallContext, Map)} — pinned
 * to pac4j 6.3.x; the signature changed in 6.4. Kept thin: call {@code super}, then read back
 * and record the stored values.</p>
 */
public class StatePoolOidcRedirectionActionBuilder extends OidcRedirectionActionBuilder {

    private final StatePool statePool;
    private final boolean pkcePoolingEnabled;
    private final boolean noncePoolingEnabled;

    /**
     * Create the builder with PKCE pooling on and nonce pooling off (the library defaults).
     */
    public StatePoolOidcRedirectionActionBuilder(final OidcClient client, final StatePool statePool) {
        this(client, statePool, true, false);
    }

    /**
     * Create the builder.
     *
     * @param pkcePoolingEnabled  whether to record the PKCE code_verifier against the state
     * @param noncePoolingEnabled whether to record the nonce against the state
     */
    public StatePoolOidcRedirectionActionBuilder(final OidcClient client, final StatePool statePool,
                                                 final boolean pkcePoolingEnabled,
                                                 final boolean noncePoolingEnabled) {
        super(client);
        this.statePool = Objects.requireNonNull(statePool, "statePool must not be null");
        this.pkcePoolingEnabled = pkcePoolingEnabled;
        this.noncePoolingEnabled = noncePoolingEnabled;
    }

    /** {@inheritDoc} */
    @Override
    protected void addStateAndNonceParameters(final CallContext ctx, final Map<String, String> params) {
        // Guarantee the client name is initialised before any pool key is derived from it.
        client.init();

        super.addStateAndNonceParameters(ctx, params);

        if (!client.getConfiguration().isWithState()) {
            return;
        }

        // super just stored the generated state in the single slot under "state"; record it in
        // the pool too (additive).
        val stateValue = params.get("state");
        if (stateValue == null || stateValue.isBlank()) {
            return;
        }
        statePool.add(ctx, client.getName(), stateValue);

        // PKCE verifier pooling (default ON): associate the verifier super stored with this
        // flow's state. The single-slot write is left intact.
        if (pkcePoolingEnabled && client.getConfiguration().findPkceMethod() != null) {
            val storedVerifier = ctx.sessionStore()
                .get(ctx.webContext(), client.getCodeVerifierSessionAttributeName());
            if (storedVerifier.isPresent() && storedVerifier.get() instanceof CodeVerifier verifier) {
                statePool.addFlowSecrets(ctx, client.getName(), stateValue, verifier.getValue(), null);
            }
        }

        // Nonce pooling (default OFF, opt-in): associate the nonce super stored with this flow's
        // state.
        if (noncePoolingEnabled && client.getConfiguration().isUseNonce()) {
            val storedNonce = ctx.sessionStore()
                .get(ctx.webContext(), client.getNonceSessionAttributeName());
            if (storedNonce.isPresent() && storedNonce.get() instanceof String nonceValue
                && !nonceValue.isBlank()) {
                statePool.addFlowSecrets(ctx, client.getName(), stateValue, null, nonceValue);
            }
        }
    }
}
