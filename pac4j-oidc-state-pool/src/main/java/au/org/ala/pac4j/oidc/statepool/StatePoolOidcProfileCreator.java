package au.org.ala.pac4j.oidc.statepool;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import lombok.val;
import org.pac4j.core.context.CallContext;
import org.pac4j.core.context.WebContext;
import org.pac4j.core.context.session.SessionStore;
import org.pac4j.core.credentials.Credentials;
import org.pac4j.core.profile.UserProfile;
import org.pac4j.core.profile.creator.ProfileCreator;
import org.pac4j.core.util.InitializableObject;
import org.pac4j.oidc.client.OidcClient;
import org.pac4j.oidc.config.OidcConfiguration;
import org.pac4j.oidc.credentials.OidcCredentials;
import org.pac4j.oidc.exceptions.OidcException;
import org.pac4j.oidc.profile.creator.OidcProfileCreator;

import java.util.Objects;
import java.util.Optional;

/**
 * A {@link ProfileCreator} decorator that resolves the expected {@code nonce} from the state pool
 * and exposes it to the delegate through a request-local session view.
 *
 * <p>The ID token's untrusted {@code nonce} claim is used only to select and consume a known
 * pooled nonce. The delegate remains responsible for signature and nonce-equality validation,
 * profile construction, user-info calls, and all other stock OIDC behavior.</p>
 *
 * <p>The real session is never mutated. Only reads of the client's nonce session key are
 * intercepted; every other session operation is forwarded unchanged.</p>
 */
public class StatePoolOidcProfileCreator extends InitializableObject implements ProfileCreator {

    private final OidcConfiguration configuration;
    private final OidcClient client;
    private final StatePool statePool;
    private final boolean noncePoolingEnabled;
    private final ProfileCreator delegate;

    /**
     * Compatibility constructor that decorates pac4j's stock {@link OidcProfileCreator}.
     */
    public StatePoolOidcProfileCreator(final OidcConfiguration configuration, final OidcClient client,
                                       final StatePool statePool, final boolean noncePoolingEnabled) {
        this(configuration, client, statePool, noncePoolingEnabled,
            new OidcProfileCreator(configuration, client));
    }

    /**
     * Create a nonce-aware decorator around the supplied profile creator.
     */
    public StatePoolOidcProfileCreator(final OidcConfiguration configuration, final OidcClient client,
                                       final StatePool statePool, final boolean noncePoolingEnabled,
                                       final ProfileCreator delegate) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.client = Objects.requireNonNull(client, "client must not be null");
        this.statePool = Objects.requireNonNull(statePool, "statePool must not be null");
        this.noncePoolingEnabled = noncePoolingEnabled;
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    }

    @Override
    protected void internalInit(final boolean forceReinit) {
        if (delegate instanceof InitializableObject initializableObject) {
            initializableObject.init(forceReinit);
        }
    }

    /**
     * Delegate profile creation, substituting a request-local nonce view only when pooled nonce
     * validation applies to these credentials.
     */
    @Override
    public Optional<UserProfile> create(final CallContext ctx, final Credentials credentials) {
        init();

        if (!shouldUsePooledNonce(credentials)) {
            return delegate.create(ctx, credentials);
        }

        final String pooledNonce = resolvePooledNonce(ctx, credentials);
        final SessionStore sessionStore = new NonceOverlaySessionStore(
            ctx.sessionStore(), client.getNonceSessionAttributeName(), pooledNonce);
        final CallContext delegateContext = new CallContext(
            ctx.webContext(), sessionStore, ctx.profileManagerFactory());
        return delegate.create(delegateContext, credentials);
    }

    private boolean shouldUsePooledNonce(final Credentials credentials) {
        if (!noncePoolingEnabled || !configuration.isUseNonce()) {
            return false;
        }
        return !(credentials instanceof OidcCredentials oidcCredentials
            && oidcCredentials.isRefreshedCredentials()
            && !configuration.isUseNonceOnRefresh());
    }

    /**
     * Resolve and consume the expected nonce, failing closed on any inconsistency.
     *
     * <p>The parsed claim is only a selector. The delegate performs full cryptographic and
     * nonce-equality validation against the value exposed by the session overlay.</p>
     */
    private String resolvePooledNonce(final CallContext ctx, final Credentials credentials) {
        if (!(credentials instanceof OidcCredentials oidcCredentials)
            || oidcCredentials.getIdToken() == null) {
            throw new OidcException("Nonce pooling is enabled but there is no ID token to validate");
        }

        final String claimedNonce = readNonceClaim(oidcCredentials);
        if (claimedNonce == null || claimedNonce.isBlank()) {
            throw new OidcException("Nonce pooling is enabled but the ID token carries no nonce claim");
        }

        val clientName = client.getName();
        if (clientName == null || clientName.isBlank()) {
            throw new OidcException("Nonce pooling cannot resolve a client name");
        }

        if (!statePool.containsNonce(ctx, clientName, claimedNonce)) {
            throw new OidcException("The ID token nonce claim is not a known pooled nonce "
                + "(unknown, expired or already used)");
        }
        if (!statePool.consumeNonceByValue(ctx, clientName, claimedNonce)) {
            throw new OidcException("The ID token nonce claim could not be consumed from the pool "
                + "(already used)");
        }

        return claimedNonce;
    }

    private static String readNonceClaim(final OidcCredentials oidcCredentials) {
        try {
            final JWTClaimsSet claims = JWTParser.parse(oidcCredentials.getIdToken()).getJWTClaimsSet();
            final Object nonceClaim = claims.getClaim("nonce");
            return nonceClaim instanceof String s ? s : null;
        } catch (final java.text.ParseException e) {
            return null;
        }
    }

    ProfileCreator getDelegate() {
        return delegate;
    }

    private static final class NonceOverlaySessionStore implements SessionStore {

        private final SessionStore delegate;
        private final String nonceKey;
        private final String nonce;

        private NonceOverlaySessionStore(final SessionStore delegate, final String nonceKey,
                                         final String nonce) {
            this.delegate = delegate;
            this.nonceKey = nonceKey;
            this.nonce = nonce;
        }

        @Override
        public Optional<String> getSessionId(final WebContext context, final boolean createSession) {
            return delegate.getSessionId(context, createSession);
        }

        @Override
        public Optional<Object> get(final WebContext context, final String key) {
            if (Objects.equals(nonceKey, key)) {
                return Optional.of(nonce);
            }
            return delegate.get(context, key);
        }

        @Override
        public void set(final WebContext context, final String key, final Object value) {
            delegate.set(context, key, value);
        }

        @Override
        public boolean destroySession(final WebContext context) {
            return delegate.destroySession(context);
        }

        @Override
        public Optional<Object> getTrackableSession(final WebContext context) {
            return delegate.getTrackableSession(context);
        }

        @Override
        public Optional<SessionStore> buildFromTrackableSession(final WebContext context,
                                                                 final Object trackableSession) {
            return delegate.buildFromTrackableSession(context, trackableSession);
        }

        @Override
        public boolean renewSession(final WebContext context) {
            return delegate.renewSession(context);
        }
    }
}
