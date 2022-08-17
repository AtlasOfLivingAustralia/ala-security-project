package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.profile.AlaOidcUserProfile
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.Json
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.util.ResourceRetriever
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata

import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.exception.CredentialsException
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import spock.lang.Specification

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

class AlaOidcAuthenticatorSpec extends Specification {

    def 'validate access_token without scope'() {

        setup:
        OIDCProviderMetadata oidcProviderMetadata = Mock() {
            1 * getJWKSetURI() >> new URI('http://localhost/jwk')
            1 * getUserInfoJWSAlgs() >> [ new JWSAlgorithm('TEST') ]
        }

        OidcConfiguration oidcConfiguration = Mock() {
            _ * findProviderMetadata() >> oidcProviderMetadata
            1 * findResourceRetriever() >> Mock(ResourceRetriever)
        }

        GroovyMock(JWTParser, global: true)
        JWTParser.parse(_) >> Mock(JWT)

        JWTClaimsSet claimsSet = GroovyMock(JWTClaimsSet)

        GroovyMock(DefaultJWTProcessor, global: true)
        new DefaultJWTProcessor() >> Mock(DefaultJWTProcessor) {
            1 * process(_, null) >> claimsSet
        }

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)

        OidcCredentials oidcCredentials = new OidcCredentials()
        oidcCredentials.accessToken = new BearerAccessToken('access_token')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        !oidcCredentials.accessToken.scope
        !oidcCredentials.userProfile
    }

    def 'access_token missing required scope'() {

        setup:
        OIDCProviderMetadata oidcProviderMetadata = Mock() {
            1 * getJWKSetURI() >> new URI('http://localhost/jwk')
            1 * getUserInfoJWSAlgs() >> [ new JWSAlgorithm('TEST') ]
        }

        OidcConfiguration oidcConfiguration = Mock() {
            _ * findProviderMetadata() >> oidcProviderMetadata
            1 * findResourceRetriever() >> Mock(ResourceRetriever)
        }

        GroovyMock(JWTParser, global: true)
        JWTParser.parse(_) >> Mock(JWT)

        JWTClaimsSet claimsSet = GroovyMock(JWTClaimsSet)
        1 * claimsSet.getStringClaim('scope') >> 'test/scope'

        GroovyMock(DefaultJWTProcessor, global: true)
        new DefaultJWTProcessor() >> Mock(DefaultJWTProcessor) {
            1 * process(_, null) >> claimsSet
        }

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)
        alaOidcAuthenticator.requiredScopes = [ 'required/scope' ]

        OidcCredentials oidcCredentials = new OidcCredentials()
        oidcCredentials.accessToken = new BearerAccessToken('access_token')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        CredentialsException ce = thrown CredentialsException
        ce.message == 'access_token with scope \'[test/scope]\' is missing required scopes [required/scope]'
    }

    def 'validate access_token with user profile'() {

        setup:
        WireMockServer wm = new WireMockServer(wireMockConfig().dynamicPort())
        wm.start()

        OIDCProviderMetadata oidcProviderMetadata = Mock() {
            1 * getUserInfoEndpointURI() >> new URI("http://localhost:${wm.port()}/userInfo")
            1 * getJWKSetURI() >> new URI('http://localhost/jwk')
            1 * getUserInfoJWSAlgs() >> [ new JWSAlgorithm('TEST') ]
        }

        OidcConfiguration oidcConfiguration = Mock() {
            _ * findProviderMetadata() >> oidcProviderMetadata
            1 * findResourceRetriever() >> Mock(ResourceRetriever)
            _ * getMappedClaims() >> [:]
        }

        GroovyMock(JWTParser, global: true)
        JWTParser.parse(_) >> Mock(JWT)

        JWTClaimsSet claimsSet = GroovyMock(JWTClaimsSet)
        1 * claimsSet.getStringClaim('scope') >> 'openid profile email'

        GroovyMock(DefaultJWTProcessor, global: true)
        new DefaultJWTProcessor() >> Mock(DefaultJWTProcessor) {
            1 * process(_, null) >> claimsSet
        }

        wm.stubFor(
                get(urlEqualTo('/userInfo'))
                .willReturn(okJson(Json.write([
                        sub: 'subject',
                        given_name: 'given_name',
                        family_name: 'family_name',
                        email: 'email@test.com'
                ])))
        )

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)
        alaOidcAuthenticator.requiredScopes = [ 'openid', 'profile', 'email' ]

        OidcCredentials oidcCredentials = new OidcCredentials()
        oidcCredentials.accessToken = new BearerAccessToken('access_token')

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        oidcCredentials.accessToken.scope == new Scope('openid', 'profile', 'email')
        oidcCredentials.userProfile instanceof AlaOidcUserProfile

        oidcCredentials.userProfile.firstName == 'given_name'
        oidcCredentials.userProfile.lastName == 'family_name'
        oidcCredentials.userProfile.email == 'email@test.com'

        cleanup:
        wm.shutdown()
    }
}
