package au.org.ala.pac4j.oidc.statepool;

import org.pac4j.core.profile.creator.AuthenticatorProfileCreator;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;

/**
 * An {@link OidcClient} pre-wired for concurrent-state support via a {@link StatePool}, with
 * PKCE {@code code_verifier} pooling (on by default) and opt-in {@code nonce} pooling.
 *
 * <p>Installs a {@link StatePoolOidcRedirectionActionBuilder}, a {@link StatePoolValueRetriever}
 * as the configuration's {@code ValueRetriever}, and (when nonce pooling is enabled) a
 * {@link StatePoolOidcProfileCreator}. All share the same {@link StatePool} instance — safe
 * because the pool is a stateless helper; isolation is per-session/per-client-name inside the
 * backing {@link StatePoolStore}.</p>
 *
 * <p>Usage:</p>
 * <pre>{@code
 * OidcConfiguration config = new OidcConfiguration();
 * // ... normal config (clientId, secret, discoveryURI, ...) ...
 * StatePoolOidcClient client = new StatePoolOidcClient(config);
 * client.setCallbackUrl("https://app.example.com/callback");
 * client.setNoncePoolingEnabled(true);  // opt-in (default off)
 * }</pre>
 */
public class StatePoolOidcClient extends OidcClient {

    private final StatePool statePool;

    /** Pool the PKCE code_verifier keyed by state. ON by default. */
    private boolean pkcePoolingEnabled = true;

    /** Pool the nonce keyed by state. OFF by default (opt-in); intercepts token validation via
     *  a custom profile creator. */
    private boolean noncePoolingEnabled = false;

    /**
     * Create the client with default pool settings (5 minute TTL, 20 concurrent states), backed
     * by a single-node {@link SessionStatePoolStore}.
     */
    public StatePoolOidcClient(final OidcConfiguration configuration) {
        this(configuration, new SessionStatePoolStore(),
            StatePool.DEFAULT_TTL_MILLIS, StatePool.DEFAULT_MAX_SIZE);
    }

    /**
     * Create the client backed by a single-node {@link SessionStatePoolStore}.
     */
    public StatePoolOidcClient(final OidcConfiguration configuration, final long ttlMillis, final int maxSize) {
        this(configuration, new SessionStatePoolStore(), ttlMillis, maxSize);
    }

    /**
     * Create the client with an explicit store (e.g. a Redis/DB-backed {@link StatePoolStore}
     * for a non-sticky cluster).
     */
    public StatePoolOidcClient(final OidcConfiguration configuration, final StatePoolStore store,
                               final long ttlMillis, final int maxSize) {
        super(configuration);
        this.statePool = new StatePool(store, ttlMillis, maxSize);
    }

    /** {@inheritDoc} */
    @Override
    protected void internalInit(final boolean forceReinit) {
        // Install retriever, redirect builder and (for nonce pooling) profile creator in init so
        // the flags set after construction are honoured. All three are set BEFORE
        // super.internalInit: super uses setXxxIfUndefined for builder and profile creator, so
        // pre-set instances win; the retriever is a plain configuration property we own outright.
        getConfiguration().setValueRetriever(
            new StatePoolValueRetriever(statePool, null, pkcePoolingEnabled));
        setRedirectionActionBuilder(new StatePoolOidcRedirectionActionBuilder(
            this, statePool, pkcePoolingEnabled, noncePoolingEnabled));
        if (noncePoolingEnabled && !(getProfileCreator() instanceof StatePoolOidcProfileCreator)) {
            final ProfileCreator configuredCreator = getProfileCreator();
            final ProfileCreator delegate = configuredCreator == null
                || configuredCreator == AuthenticatorProfileCreator.INSTANCE
                ? new OidcProfileCreator(getConfiguration(), this)
                : configuredCreator;
            setProfileCreator(new StatePoolOidcProfileCreator(
                getConfiguration(), this, statePool, true, delegate));
        }
        super.internalInit(forceReinit);
    }

    /** The shared state pool. */
    public StatePool getStatePool() {
        return statePool;
    }

    /** Whether PKCE code_verifier pooling is enabled. Default {@code true}. */
    public boolean isPkcePoolingEnabled() {
        return pkcePoolingEnabled;
    }

    /**
     * Enable or disable PKCE code_verifier pooling. When off, the verifier is read from its
     * single session slot (stock pac4j behaviour). Set before the client is used (read when the
     * redirect builder is installed during init).
     */
    public void setPkcePoolingEnabled(final boolean pkcePoolingEnabled) {
        this.pkcePoolingEnabled = pkcePoolingEnabled;
    }

    /** Whether nonce pooling is enabled. Default {@code false} (opt-in). */
    public boolean isNoncePoolingEnabled() {
        return noncePoolingEnabled;
    }

    /**
     * Enable or disable nonce pooling. When enabled AND {@code useNonce} is on, the expected
     * nonce is resolved from the pool by a {@link StatePoolOidcProfileCreator} instead of the
     * single session slot. Set before the client is used.
     */
    public void setNoncePoolingEnabled(final boolean noncePoolingEnabled) {
        this.noncePoolingEnabled = noncePoolingEnabled;
    }
}
