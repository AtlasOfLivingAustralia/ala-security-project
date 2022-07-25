package au.org.ala.ws.tokens

import au.org.ala.web.Pac4jContextProvider
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
import com.nimbusds.oauth2.sdk.auth.Secret
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.AccessToken
import groovy.util.logging.Slf4j
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.profile.ProfileManager
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.profile.OidcProfile

/**
 * Component for getting access tokens for using on web service requests.
 */
@Slf4j
class TokenService {

    final String oidcScopes
    final String jwtScopes
    final List<String> finalScopes

    private final Config config

    private final OidcConfiguration oidcConfiguration

    private final Pac4jContextProvider pac4jContextProvider

    private final SessionStore sessionStore

    private final TokenClient tokenClient

    TokenService(Config config, OidcConfiguration oidcConfiguration, Pac4jContextProvider pac4jContextProvider,
                 SessionStore sessionStore, TokenClient tokenClient, String oidcScopes, String jwtScopes) {
        this.config = config
        this.oidcConfiguration = oidcConfiguration
        this.pac4jContextProvider = pac4jContextProvider
        this.sessionStore = sessionStore
        this.tokenClient = tokenClient
        this.oidcScopes = oidcScopes
        this.jwtScopes = jwtScopes
        this.finalScopes = (oidcScopes.tokenize(' ') + jwtScopes.tokenize(' ')).findAll().toSet().toList()
    }

    ProfileManager getProfileManager() {
        def context = pac4jContextProvider.webContext()
        final ProfileManager manager = new ProfileManager(context, sessionStore)
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
        def token
        if (requireUser) {
            token = profileManager.getProfile(OidcProfile).map { it.accessToken }.orElse(null)
        } else {
            if (oidcConfiguration) {
                def tokenRequest = new TokenRequest(
                        oidcConfiguration.findProviderMetadata().getTokenEndpointURI(),
                        new ClientSecretBasic(new ClientID(oidcConfiguration.clientId), new Secret(oidcConfiguration.secret)),
                        new ClientCredentialsGrant(),
                        new Scope(*finalScopes)
                )
                def credentials = tokenClient.executeTokenRequest(tokenRequest)
                token = credentials.accessToken
            } else {
                log.debug("Not generating token because OIDC is not configured")
                token = null
            }
        }
        return token
    }

}
