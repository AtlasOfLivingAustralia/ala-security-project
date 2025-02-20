package au.org.ala.ws.security.authenticator

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.oauth2.sdk.id.Issuer
import groovy.time.TimeCategory
import org.pac4j.core.context.CallContext
import org.pac4j.core.context.WebContext
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.creator.ProfileCreator
import org.pac4j.jwt.profile.JwtProfile
import org.pac4j.oidc.config.OidcConfiguration

import spock.lang.Specification

import static au.org.ala.ws.security.JwtUtils.*

class AlaOidcAuthenticatorSpec extends Specification {

    JWKSet jwkSet = jwkSet('test.jwks')

    def 'validate access_token without scope'() {

        setup:
        OidcConfiguration oidcConfiguration = Mock()
        ProfileCreator profileCreator = Mock()

        AlaJwtAuthenticator alaOidcAuthenticator = new AlaJwtAuthenticator() // oidcConfiguration, profileCreator
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)


//        OidcCredentials oidcCredentials = new OidcCredentials()
//        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, [].toSet()))
        var credentials = new TokenCredentials(generateJwt(jwkSet, [].toSet()))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        Optional<Credentials> creds = alaOidcAuthenticator.validate(new CallContext(context, sessionStore), credentials)

        then:
        creds.isPresent()
        creds.get().getToken() == credentials.getToken()
        creds.get().userProfile instanceof JwtProfile
        var jwtProfile = creds.get().userProfile as JwtProfile
        jwtProfile.roles.empty
        jwtProfile.issuer == 'http://localhost'
        jwtProfile.subject == 'sub'
        jwtProfile.audience == ['some-aud']
//        credentials.userProfile instanceof AlaM2MUserProfile
//        credentials.userProfile.roles.empty
//        credentials.userProfile.permissions.empty
//        credentials.userProfile.clientId == 'sub'
//        credentials.userProfile.issuer == 'http://localhost'
//        credentials.userProfile.audience == ['some-aud']
    }

    def 'access_token missing required scope'() {

        setup:
        OidcConfiguration oidcConfiguration = Mock()
        ProfileCreator profileCreator = Mock()

        AlaJwtAuthenticator alaOidcAuthenticator = new AlaJwtAuthenticator() // oidcConfiguration, profileCreator
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        alaOidcAuthenticator.requiredScopes = [ 'required/scope' ]

        var credentials = new TokenCredentials(generateJwt(jwkSet, ['test/scope'].toSet()))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        alaOidcAuthenticator.validate(new CallContext(context, sessionStore), credentials)

        then:
        CredentialsException ce = thrown CredentialsException
        ce.message == 'access_token with scope \'[test/scope]\' is missing required scopes [required/scope]'
    }

    // TODO move to AlaOidcProfileCreatorSpec
//    def 'validate access_token with userId'() {
//
//        setup:
//        OidcConfiguration oidcConfiguration = Mock()
//        ProfileCreator profileCreator = Mock()
//
//        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration, profileCreator)
//        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
//        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
//        alaOidcAuthenticator.requiredClaims = []
//        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)
//
//        alaOidcAuthenticator.userIdClaim = 'username'
//
//        OidcCredentials oidcCredentials = new OidcCredentials()
//        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
//                .subject('sub')
//                .issuer(alaOidcAuthenticator.issuer.value)
//                .notBeforeTime(new Date())
//                .expirationTime(use(TimeCategory) { new Date() + 1.minute })
//                .audience('aud')
//                .issueTime(new Date())
//                .claim('username', 'user-id')
//                .build()
//
//        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, jwtClaims))
//
//        WebContext context = Mock()
//        SessionStore sessionStore = Mock()
//
//        when:
//        alaOidcAuthenticator.validate(new CallContext(context, sessionStore), oidcCredentials)
//
//        then:
//        oidcCredentials.userProfile instanceof AlaUserProfile
//        oidcCredentials.userProfile.userId == 'user-id'
//    }

    def 'validate access_token with scopes'() {

        setup:
        OidcConfiguration oidcConfiguration = Mock()
        ProfileCreator profileCreator = Mock()

        AlaJwtAuthenticator alaOidcAuthenticator = new AlaJwtAuthenticator() // oidcConfiguration, profileCreator
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        alaOidcAuthenticator.requiredScopes = [ 'some:test' ]

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .subject('sub')
                .issuer(alaOidcAuthenticator.issuer.value)
                .notBeforeTime(new Date())
                .expirationTime(use(TimeCategory) { new Date() + 1.minute })
                .audience('aud')
                .issueTime(new Date())
                .claim('username', 'user-id')
                .claim('scope', ['oidc','some:test'])
                .build()

        var credentials = new TokenCredentials(generateJwt(jwkSet, jwtClaims))

        WebContext context = Mock()
        SessionStore sessionStore = Mock()

        when:
        Optional<Credentials> creds = alaOidcAuthenticator.validate(new CallContext(context, sessionStore), credentials)

        then:
        creds.isPresent()
        creds.get().getToken() == credentials.getToken()
        creds.get().userProfile instanceof JwtProfile
        var jwtProfile = creds.get().userProfile as JwtProfile
        jwtProfile.roles.empty
        jwtProfile.issuer == 'http://localhost'
        jwtProfile.subject == 'sub'
        jwtProfile.audience == ['aud']

//        oidcCredentials.userProfile instanceof AlaOidcUserProfile
//        oidcCredentials.userProfile.userId == 'user-id'
//        oidcCredentials.userProfile.permissions.containsAll(['oidc','some:test'])
//        oidcCredentials.userProfile.accessToken.scope.contains('oidc')
//        oidcCredentials.userProfile.accessToken.scope.contains('some:test')
    }

    // TODO Move to AlaOidcProfileCreatorSpec
//    def 'validate access_token with roles'() {
//
//        setup:
//        OidcConfiguration oidcConfiguration = Mock()
//        ProfileCreator profileCreator = Mock()
//
//        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration, profileCreator)
//        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
//        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
//        alaOidcAuthenticator.requiredClaims = []
//        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)
//
//        alaOidcAuthenticator.userIdClaim = 'username'
//        alaOidcAuthenticator.rolesFromAccessToken = true
//        alaOidcAuthenticator.accessTokenRoleClaims = [ 'roles' ]
//        alaOidcAuthenticator.rolePrefix = 'ROLE_'
//
//        OidcCredentials oidcCredentials = new OidcCredentials()
//        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
//                .subject('sub')
//                .issuer(alaOidcAuthenticator.issuer.value)
//                .notBeforeTime(new Date())
//                .expirationTime(use(TimeCategory) { new Date() + 1.minute })
//                .audience('aud')
//                .issueTime(new Date())
//                .claim('username', 'user-id')
//                .claim('roles', [ 'user', 'admin' ])
//                .build()
//
//        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, jwtClaims))
//
//        WebContext context = Mock()
//        SessionStore sessionStore = Mock()
//
//        when:
//        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)
//
//        then:
//        oidcCredentials.userProfile.roles == Set.of('ROLE_USER', 'ROLE_ADMIN')
//    }

    // TODO Move to AlaOidcProfileCreatorSpec
//    def 'validate access_token with user profile'() {
//
//        setup:
//
//        OIDCProviderMetadata oidcProviderMetadata = Mock() {
//            _ * getUserInfoEndpointURI() >> new URI("http://localhost/userInfo")
//        }
//
//        OidcConfiguration oidcConfiguration = Mock() {
//            _ * findProviderMetadata() >> oidcProviderMetadata
//            _ * getMappedClaims() >> [:]
//        }
//
//        ProfileCreator profileCreator = Mock() {
//            1 * create(_, _, _) >> Optional.of(new OidcProfile() {
//                @Override
//                Map<String, Object> getAttributes() {
//                    return [
//                            sub: 'subject',
//                            given_name: 'given_name',
//                            family_name: 'family_name',
//                            email: 'email@test.com'
//                    ]
//                }
//            })
//        }
//
//        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration, profileCreator)
//        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
//        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
//        alaOidcAuthenticator.requiredClaims = []
//        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)
//
//        alaOidcAuthenticator.requiredScopes = [ 'openid', 'profile', 'email' ]
//
//
//        OidcCredentials oidcCredentials = new OidcCredentials()
//        oidcCredentials.accessToken = new BearerAccessToken(generateJwt(jwkSet, [ 'openid', 'profile', 'email' ].toSet()))
//
//        WebContext context = Mock()
//        SessionStore sessionStore = Mock()
//
//        when:
//        alaOidcAuthenticator.validate(oidcCredentials, context, sessionStore)
//
//        then:
//        oidcCredentials.accessToken.scope == new Scope('openid', 'profile', 'email')
//        oidcCredentials.userProfile instanceof AlaOidcUserProfile
//
//        oidcCredentials.userProfile.givenName == 'given_name'
//        oidcCredentials.userProfile.familyName == 'family_name'
//        oidcCredentials.userProfile.email == 'email@test.com'
//    }
}
