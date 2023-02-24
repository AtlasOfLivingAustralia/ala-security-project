package au.org.ala.ws.tokens

import au.org.ala.web.Pac4jContextProvider
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
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
    def pac4jContextProvider
    def sessionStore
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
        pac4jContextProvider = new Pac4jContextProvider() {
            @Override
            WebContext webContext() {
                JEEContextFactory.INSTANCE.newContext(request, response)
            }
        }
        sessionStore = JEESessionStore.INSTANCE
        tokenClient = Mock(TokenClient)
        tokenService = new TokenService(config, oidcConfiguration, pac4jContextProvider, sessionStore, tokenClient, 'openid profile', 'client-id', 'client-secret', 'openid ala:internal users:read', false)
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

    def 'test token service requireUser false with cache'() {
        setup:
        def tokenService = new TokenService(config, oidcConfiguration, pac4jContextProvider, sessionStore, tokenClient,
                'openid profile', 'client-id', 'client-secret', 'openid ala:internal users:read', true)

        def oidcCredentials = new OidcCredentials().tap {
            it.accessToken = new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 2l, null)
            it.refreshToken = new RefreshToken("asdfasdfasdfasdf")
        }

        def oidcCredentials2 = new OidcCredentials().tap {
            it.accessToken = new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNjc2MjM5MDIyfQ.wF1li4R8Gu0h54T_DwxfKGRAtvR1MV43wdpuc2o17Lo', 2l, null)
            it.refreshToken = new RefreshToken("qwerqwerqwer")
        }

//        tokenService.cachedCredentials = null
        when:
        def token1
        def token2
        synchronized (tokenService.lock) {
            token1 = tokenService.getAuthToken(false)
            token2 = tokenService.getAuthToken(false)
        }
        then: "cached token returned for second call"
        1 * tokenClient.executeTokenRequest(_) >> oidcCredentials
        token1 == token2

        when:

        sleep(3000)
        def token3 = tokenService.getAuthToken(false)

        then: "refresh token grant used"
        1 * tokenClient.executeTokenRequest(_) >> oidcCredentials2
        token1 != token3

    }
}