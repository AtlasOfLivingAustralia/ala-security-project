package au.org.ala.ws.service

import au.org.ala.web.Pac4jContextProvider
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant
import com.nimbusds.oauth2.sdk.ParseException
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.TokenErrorResponse
import com.nimbusds.oauth2.sdk.TokenRequest
import com.nimbusds.oauth2.sdk.id.ClientID
import com.nimbusds.oauth2.sdk.token.AccessToken
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser
import grails.core.GrailsApplication
import groovy.util.logging.Slf4j
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.exception.TechnicalException
import org.pac4j.core.profile.ProfileManager
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import org.pac4j.oidc.profile.OidcProfile
import org.springframework.beans.factory.annotation.Autowired

@Slf4j
class JwtTokenService {

    GrailsApplication grailsApplication

    @Autowired(required = false)
    private final Config config

    @Autowired(required = false)
    private final OidcConfiguration oidcConfiguration

    @Autowired(required = false)
    private final Pac4jContextProvider pac4jContextProvider

    @Autowired(required = false)
    private final SessionStore sessionStore

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
            def oidcScopes = grailsApplication.config.getProperty('security.oidc.scopes', String, 'openid')
            def requestedScopes = grailsApplication.config.getProperty('webservice.jwt-scopes', String, 'openid')
            List<String> finalScopes = (oidcScopes.tokenize(' ') + requestedScopes.tokenize(' ')).findAll().toSet().toList()
            Scope scope = new Scope(*finalScopes)

            if (oidcConfiguration) {
                def tokenRequest = new TokenRequest(
                        oidcConfiguration.findProviderMetadata().getTokenEndpointURI(),
                        new ClientID(oidcConfiguration.clientId),
                        new ClientCredentialsGrant(),
                        scope,
                        null,
                        null,
                        [client_secret: [oidcConfiguration.secret]]
                )
                def credentials = executeTokenRequest(tokenRequest)
                token = credentials.accessToken
            } else {
                log.debug("Not generating token because OIDC is not configured")
                token = null
            }
        }
        return token
    }

    private OidcCredentials executeTokenRequest(TokenRequest request) throws IOException, ParseException {
        var tokenHttpRequest = request.toHTTPRequest()
        if (oidcConfiguration) {
            oidcConfiguration.configureHttpRequest(tokenHttpRequest)
        }

        def httpResponse = tokenHttpRequest.send()
        log.debug("Token response: status={}, content={}", httpResponse.getStatusCode(),
                httpResponse.getContent())

        def response = OIDCTokenResponseParser.parse(httpResponse)
        if (response instanceof TokenErrorResponse) {
            def errorObject = ((TokenErrorResponse) response).getErrorObject()
            throw new TechnicalException("Bad token response, error=" + errorObject.getCode() + "," +
                    " description=" + errorObject.getDescription())
        }
        log.debug("Token response successful")
        def tokenSuccessResponse = (OIDCTokenResponse) response

        def credentials = new OidcCredentials()
        def oidcTokens = tokenSuccessResponse.getOIDCTokens()
        credentials.setAccessToken(oidcTokens.getAccessToken())
        credentials.setRefreshToken(oidcTokens.getRefreshToken())
        if (oidcTokens.getIDToken() != null) {
            credentials.setIdToken(oidcTokens.getIDToken())
        }
        return credentials
    }

}
