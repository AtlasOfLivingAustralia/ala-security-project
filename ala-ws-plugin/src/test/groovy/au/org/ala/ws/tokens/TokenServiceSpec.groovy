package au.org.ala.ws.tokens

import au.org.ala.web.Pac4jContextProvider
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.SubjectType
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import org.pac4j.core.config.Config
import org.pac4j.core.context.WebContext
import org.pac4j.core.util.Pac4jConstants
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import org.pac4j.oidc.profile.OidcProfile
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import spock.lang.Specification

import javax.servlet.http.HttpServletRequest

class TokenServiceSpec extends Specification {

    def tokenUri = 'https://example.org/token'

    def config
    def oidcConfiguration
    HttpServletRequest request
    TokenClient tokenClient
    TokenService tokenService

    def setup() {
        config = Stub(Config)
        oidcConfiguration = Stub(OidcConfiguration)
        oidcConfiguration.clientId >> 'clientid'
        oidcConfiguration.secret >> 'secret'
        def providerMetadata = new OIDCProviderMetadata(new Issuer('https://example.org/'), [SubjectType.PUBLIC], 'https://example.org/jwks'.toURI())
        providerMetadata.setTokenEndpointURI(tokenUri.toURI())
        oidcConfiguration.findProviderMetadata() >> providerMetadata
        request = new MockHttpServletRequest()
        request.getSession(true)
        def response = new MockHttpServletResponse()
        def pac4jContextProvider = new Pac4jContextProvider() {
            @Override
            WebContext webContext() {
                JEEContextFactory.INSTANCE.newContext(request, response)
            }
        }
        def sessionStore = JEESessionStore.INSTANCE
        tokenClient = Mock(TokenClient)
        tokenService = new TokenService(config, oidcConfiguration, pac4jContextProvider, sessionStore, tokenClient, 'openid profile', 'openid ala:internal users:read')
    }


    def 'test token service requireUser false'() {
        setup:
        def oidcCredentials = new OidcCredentials().tap { it.accessToken = new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c') }

        when:
        def token = tokenService.getAuthToken(false)

        then:
        1 * tokenClient.executeTokenRequest(_) >> oidcCredentials
        token != null
    }

    def 'test token service requireUser true'() {
        setup:
        request.getSession(false).setAttribute(Pac4jConstants.USER_PROFILES, ['oidc': new OidcProfile().tap { it.accessToken = new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c') }])

        when:
        def token = tokenService.getAuthToken(true)

        then:
        0 * tokenClient.executeTokenRequest(_)
        token != null
    }
}