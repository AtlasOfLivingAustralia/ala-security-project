package au.org.ala.ws.security.authenticator

import au.org.ala.ws.security.profile.AlaOidcUserProfile
import au.org.ala.ws.security.profile.AlaUserProfile
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.common.Json
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.Scope
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.token.BearerAccessToken
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
import groovy.time.TimeCategory
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.exception.CredentialsException
import org.pac4j.oidc.config.OidcConfiguration
import org.pac4j.oidc.credentials.OidcCredentials
import spock.lang.Specification

import static au.org.ala.ws.security.JwtUtils.*

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

class AlaOidcAuthenticatorSpec extends Specification {

    JWKSet jwkSet = jwkSet('test.jwks')

    def 'validate access_token without scope'() {

        setup:
        OidcConfiguration oidcConfiguration = Mock()

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)


        OidcCredentials oidcCredentials = new OidcCredentials()
        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, [].toSet()))

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
        OidcConfiguration oidcConfiguration = Mock()

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        alaOidcAuthenticator.requiredScopes = [ 'required/scope' ]

        OidcCredentials oidcCredentials = new OidcCredentials()
        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, [ 'test/scope' ].toSet()))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        CredentialsException ce = thrown CredentialsException
        ce.message == 'access_token with scope \'test/scope\' is missing required scopes [required/scope]'
    }

    def 'validate access_token with userId'() {

        setup:
        OidcConfiguration oidcConfiguration = Mock()

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        alaOidcAuthenticator.userIdClaim = 'username'

        OidcCredentials oidcCredentials = new OidcCredentials()
        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .subject('sub')
                .issuer(alaOidcAuthenticator.issuer.value)
                .notBeforeTime(new Date())
                .expirationTime(use(TimeCategory) { new Date() + 1.minute })
                .audience('aud')
                .issueTime(new Date())
                .claim('username', 'user-id')
                .build()

        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, jwtClaims))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        oidcCredentials.userProfile instanceof AlaUserProfile
        oidcCredentials.userProfile.userId == 'user-id'
    }


    def 'validate access_token with roles'() {

        setup:
        OidcConfiguration oidcConfiguration = Mock()

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration)
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        alaOidcAuthenticator.userIdClaim = 'username'
        alaOidcAuthenticator.rolesFromAccessToken = true
        alaOidcAuthenticator.accessTokenRoleClaims = [ 'roles' ]
        alaOidcAuthenticator.rolePrefix = 'ROLE_'

        OidcCredentials oidcCredentials = new OidcCredentials()
        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .subject('sub')
                .issuer(alaOidcAuthenticator.issuer.value)
                .notBeforeTime(new Date())
                .expirationTime(use(TimeCategory) { new Date() + 1.minute })
                .audience('aud')
                .issueTime(new Date())
                .claim('username', 'user-id')
                .claim('roles', [ 'user', 'admin' ])
                .build()

        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, jwtClaims))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        oidcCredentials.userProfile.roles == Set.of('ROLE_USER', 'ROLE_ADMIN')
    }

    def 'validate access_token with user profile'() {

        setup:
        WireMockServer wm = new WireMockServer(wireMockConfig().dynamicPort())
        wm.start()

        OIDCProviderMetadata oidcProviderMetadata = Mock() {
            _ * getUserInfoEndpointURI() >> new URI("http://localhost:${wm.port()}/userInfo")
        }

        OidcConfiguration oidcConfiguration = Mock() {
            _ * findProviderMetadata() >> oidcProviderMetadata
            _ * getMappedClaims() >> [:]
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
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        alaOidcAuthenticator.requiredScopes = [ 'openid', 'profile', 'email' ]


        OidcCredentials oidcCredentials = new OidcCredentials()
        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, [ 'openid', 'profile', 'email' ].toSet()))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)

        then:
        oidcCredentials.accessToken.scope == new Scope('openid', 'profile', 'email')
        oidcCredentials.userProfile instanceof AlaOidcUserProfile

        oidcCredentials.userProfile.givenName == 'given_name'
        oidcCredentials.userProfile.familyName == 'family_name'
        oidcCredentials.userProfile.email == 'email@test.com'

        cleanup:
        wm.shutdown()
    }
}
