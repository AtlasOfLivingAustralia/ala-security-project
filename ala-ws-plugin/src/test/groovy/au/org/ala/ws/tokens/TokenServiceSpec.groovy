package au.org.ala.ws.tokens

import au.org.ala.web.Pac4jContextProvider
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.oauth2.sdk.token.RefreshToken
import com.nimbusds.openid.connect.sdk.SubjectType
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import com.nimbusds.openid.connect.sdk.token.OIDCTokens
import org.pac4j.core.config.Config
import org.pac4j.core.context.FrameworkParameters
import org.pac4j.core.context.WebContext
import org.pac4j.core.util.Pac4jConstants
import org.pac4j.jee.adapter.JEEFrameworkAdapter
import org.pac4j.jee.context.JEEContextFactory
import org.pac4j.jee.context.JEEFrameworkParameters
import org.pac4j.jee.context.session.JEESessionStoreFactory
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.metadata.StaticOidcOpMetadataResolver
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
    def sessionStoreFactory
    HttpServletRequest request
    TokenClient tokenClient
    TokenService tokenService

    def setup() {
        config = new Config()
        JEEFrameworkAdapter.INSTANCE.applyDefaultSettingsIfUndefined(config)
        oidcConfiguration = new OidcConfiguration()
        oidcConfiguration.clientId = 'clientid'
        oidcConfiguration.secret = 'secret'
        oidcConfiguration.discoveryURI = 'classpath:metadata.json'
        def providerMetadata = new OIDCProviderMetadata(new Issuer('https://example.org/'), [SubjectType.PUBLIC], 'https://example.org/jwks'.toURI())
        providerMetadata.tokenEndpointURI = tokenUri.toURI()
        providerMetadata.setIDTokenJWSAlgs([JWSAlgorithm.RS256])
        providerMetadata.tokenEndpointAuthMethods = [ClientAuthenticationMethod.CLIENT_SECRET_BASIC]
        def opMetadataResolver = new StaticOidcOpMetadataResolver(oidcConfiguration, providerMetadata)
        opMetadataResolver.init()
        oidcConfiguration.opMetadataResolver = opMetadataResolver
        request = new MockHttpServletRequest()
        request.getSession(true)
        def response = new MockHttpServletResponse()
        pac4jContextProvider = new Pac4jContextProvider() {
            @Override
            WebContext webContext() {
                JEEContextFactory.INSTANCE.newContext(new JEEFrameworkParameters(request, response))
            }

            @Override
            FrameworkParameters frameworkParameters() {
                new JEEFrameworkParameters(request, response)
            }
        }
        sessionStoreFactory = JEESessionStoreFactory.INSTANCE
        tokenClient = Mock(TokenClient)
        tokenService = new TokenService(config, oidcConfiguration, pac4jContextProvider, sessionStoreFactory, tokenClient, 'client-id', 'client-secret', 'openid ala:internal users:read', false)
    }


    def 'test token service requireUser false'() {
        setup:
        def oidcCredentials = new OIDCTokens(new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'), null)

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
        def tokenService = new TokenService(config, oidcConfiguration, pac4jContextProvider, sessionStoreFactory, tokenClient,
                'client-id', 'client-secret', 'openid ala:internal users:read', true)

        def oidcCredentials = new OIDCTokens(
            new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c', 2l, null),
            new RefreshToken("asdfasdfasdfasdf")
        )

        def oidcCredentials2 = new OIDCTokens(
            new BearerAccessToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNjc2MjM5MDIyfQ.wF1li4R8Gu0h54T_DwxfKGRAtvR1MV43wdpuc2o17Lo', 2l, null),
            new RefreshToken("qwerqwerqwer")
        )

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