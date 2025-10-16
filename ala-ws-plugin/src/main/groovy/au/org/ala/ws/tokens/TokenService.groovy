package au.org.ala.ws.tokens

import au.org.ala.web.Pac4jContextProvider
import com.google.common.annotations.VisibleForTesting
import com.nimbusds.oauth2.sdk.AuthorizationGrant
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant
import com.nimbusds.oauth2.sdk.RefreshTokenGrant
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT
import com.nimbusds.oauth2.sdk.auth.ClientSecretPost
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.token.OIDCTokens
import groovy.util.logging.Slf4j
import org.grails.web.util.WebUtils
import org.pac4j.core.adapter.FrameworkAdapter
import org.pac4j.core.config.Config
import org.pac4j.core.context.FrameworkParameters
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStoreFactory
import org.pac4j.core.profile.ProfileManager
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import org.pac4j.oidc.profile.OidcProfile

/**
 * Component for getting access tokens for using on web service requests.
 */
@Slf4j
class TokenService {

    final boolean cacheTokens

    final String clientId
    final String clientSecret

    final String jwtScopes
    final List<String> finalScopes

    // mutable to break circular spring dependency
    Config config

    private final OidcConfiguration oidcConfiguration

    private final Pac4jContextProvider pac4jContextProvider

    private final SessionStoreFactory sessionStoreFactory

    private final TokenClient tokenClient

    TokenService(Config config, OidcConfiguration oidcConfiguration, Pac4jContextProvider pac4jContextProvider,
                 SessionStoreFactory sessionStoreFactory, TokenClient tokenClient, String clientId, String clientSecret, String jwtScopes,
                 boolean cacheTokens) {
        this(oidcConfiguration, pac4jContextProvider, sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens)
        this.config = config
    }

    TokenService(OidcConfiguration oidcConfiguration, Pac4jContextProvider pac4jContextProvider,
                 SessionStoreFactory sessionStoreFactory, TokenClient tokenClient, String clientId, String clientSecret, String jwtScopes,
                 boolean cacheTokens) {
        this(oidcConfiguration, sessionStoreFactory, tokenClient, clientId, clientSecret, jwtScopes, cacheTokens)
        this.pac4jContextProvider = pac4jContextProvider
    }

    TokenService(OidcConfiguration oidcConfiguration, SessionStoreFactory sessionStoreFactory, TokenClient tokenClient,
                 String clientId, String clientSecret, String jwtScopes, boolean cacheTokens) {
        this.cacheTokens = cacheTokens
        this.config = config
        this.oidcConfiguration = oidcConfiguration
        this.sessionStoreFactory = sessionStoreFactory
        this.tokenClient = tokenClient

        this.clientId = clientId
        this.clientSecret = clientSecret
        this.jwtScopes = jwtScopes
        if (jwtScopes) {
            this.finalScopes = jwtScopes.tokenize(' ').findAll().toSet().toList()
        }
    }

    ProfileManager getProfileManager() {
        final WebContext context
        final FrameworkParameters frameworkParameters
        if (pac4jContextProvider) {
            context = pac4jContextProvider.webContext()
            frameworkParameters = pac4jContextProvider.frameworkParameters()
        } else {
            FrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)
            def gwr = WebUtils.retrieveGrailsWebRequest()
            def request = gwr.request
            def response = gwr.response
            frameworkParameters = new JEEFrameworkParameters(request, response)
            context = config.getWebContextFactory().newContext(frameworkParameters)
        }

        final ProfileManager manager = config.profileManagerFactory.apply(context, sessionStoreFactory.newSessionStore(frameworkParameters))
        manager.config = config
        return manager
    }

    /**
     * Get an access token.  Will return the current user's access token or if there is no
     * current user, will request a client credentials grant based access token for this app.
     * @param requireUser Whether the auth token must belong to an individual user (setting this to true will disable requesting a client credentials based app JWT)
     * @return The access token
     */
    AccessToken getAuthToken(boolean requireUser) {
        AccessToken token
        if (requireUser) {
            token = profileManager.getProfile(OidcProfile).map { it.accessToken }.orElse(null)
        } else {
            def credentials
            if (oidcConfiguration) {
                if (cacheTokens) {
                    credentials = getOrRefreshToken()
                } else {
                    credentials = clientCredentialsToken()
                }
                token = credentials?.accessToken
            } else {
                log.debug("Not generating token because OIDC is not configured")
                token = null
            }
        }
        return token
    }

    private long expiryWindow = 1 // 1 second
    private volatile transient OIDCTokens cachedCredentials
    private volatile transient long cachedCredentialsLifetime = 0
    @VisibleForTesting
    final Object lock = new Object()

    private OIDCTokens getOrRefreshToken() {

        long now = System.currentTimeSeconds() - expiryWindow

        def lifetime = cachedCredentialsLifetime
        if (lifetime == 0 || now >= lifetime) {
            synchronized (lock) {
                lifetime = cachedCredentialsLifetime
                if (lifetime == 0 || now >= lifetime) {
                    def credentials = tokenSupplier(cachedCredentials)
                    cachedCredentials = credentials
                    cachedCredentialsLifetime = System.currentTimeSeconds() + credentials.accessToken.lifetime
                    return credentials
                }
            }
        }
        return cachedCredentials
    }

    private OIDCTokens tokenSupplier(OIDCTokens existingCredentials) {
        OIDCTokens credentials = null
        if (existingCredentials && existingCredentials.refreshToken) {
            try {
                log.debug("Refreshing existing token")
                credentials = refreshToken(existingCredentials.refreshToken)
            } catch (e) {
                log.warn("Couldn't get refresh token from {}", existingCredentials.refreshToken, e)
            }
        }
        if (!credentials) { // no refresh token or refresh token grant failed
            log.debug("Requesting new client credentials token")
            credentials = clientCredentialsToken()
        }
        return credentials
    }

    private OIDCTokens clientCredentialsToken() {
        return sendTokenRequest(new ClientCredentialsGrant())
    }


    private OIDCTokens refreshToken(RefreshToken refreshToken) {
        return sendTokenRequest(new RefreshTokenGrant(refreshToken))
    }

    private OIDCTokens sendTokenRequest(AuthorizationGrant grant) {
        def metadata = oidcConfiguration.getOpMetadataResolver().load()
        def clientAuthentication = getClientAuthentication(metadata)
        def tokenRequest = new TokenRequest(
                metadata.tokenEndpointURI,
                clientAuthentication,
                grant,
                finalScopes ? new Scope(*finalScopes) : new Scope()
        )
        return tokenClient.executeTokenRequest(tokenRequest)
    }

    private ClientAuthentication getClientAuthentication(OIDCProviderMetadata metadata) {
        def clientAuthentication
        def methods = metadata.tokenEndpointAuthMethods
        if (methods.isEmpty() || methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            // default to basic auth
            clientAuthentication = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret))
        } else if (methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_POST)) {
            clientAuthentication = new ClientSecretPost(new ClientID(clientId), new Secret(clientSecret))
            // TODO this client auth method needs to be tested but currently isn't required so is left unimplemented
//        } else if (methods.contains(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
//            clientAuthentication = new ClientSecretJWT(new ClientID(clientId), metadata.getJWKSetURI(), metadata.tokenEndpointJWSAlgs.first(), new Secret(clientSecret))
        } else {
            throw new UnsupportedOperationException("Unsupported token endpoint auth methods: ${metadata.tokenEndpointAuthMethods}")
        }
        return clientAuthentication
    }


}
