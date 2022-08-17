package au.org.ala.ws.security

import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator
import org.pac4j.core.config.Config
import org.pac4j.core.context.session.SessionStore
import org.pac4j.core.credentials.Credentials
import org.pac4j.core.credentials.TokenCredentials
import org.pac4j.core.credentials.authenticator.Authenticator
import org.pac4j.core.credentials.extractor.CredentialsExtractor
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.UserProfile
import org.pac4j.http.client.direct.DirectBearerAuthClient
import org.pac4j.oidc.profile.OidcProfile
import spock.lang.Specification

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class AlaWebServiceAuthUtilsSpec extends Specification {

    def 'get user profile'() {

        setup:
        AlaWebServiceAuthUtils alaWebServiceAuthUtils = new AlaWebServiceAuthUtils()

        alaWebServiceAuthUtils.jwtProperties = new JwtProperties()

        CredentialsExtractor credentialsExtractor = Mock() {
            // extract the access_token
            1 * extract(_, _) >> Optional.of(new TokenCredentials('access_token'))
        }

        Authenticator userInfoOidcAuthenticator = Mock() {
            // validate the access_token, add user info to the credentials
            1 * validate(_, _, _) >> { args ->
                Credentials credentials = args[0]
                credentials.userProfile = new OidcProfile()
                credentials.userProfile.addAttribute('email', 'email@test.com')
            }
        }

        JwtAuthenticator jwtAuthenticator = Mock() {
            0 * validate(_, _, _)
        }

        alaWebServiceAuthUtils.config = new Config()
        alaWebServiceAuthUtils.config.sessionStore = Mock(SessionStore)
        alaWebServiceAuthUtils.directClient = new DirectBearerAuthClient()
        alaWebServiceAuthUtils.directClient.credentialsExtractor = credentialsExtractor
        alaWebServiceAuthUtils.directClient.authenticator = userInfoOidcAuthenticator
        alaWebServiceAuthUtils.jwtAuthenticator = jwtAuthenticator

        HttpServletRequest request = Mock(HttpServletRequest)
        HttpServletResponse response = Mock(HttpServletResponse)

        when:
        Optional<UserProfile> userProfile = alaWebServiceAuthUtils.oidcInterceptor(request, response)

        then:

        userProfile.isPresent()
        userProfile.get().attributes['email'] == 'email@test.com'
    }

    def 'missing user profile'() {

        setup:
        AlaWebServiceAuthUtils alaWebServiceAuthUtils = new AlaWebServiceAuthUtils()

        alaWebServiceAuthUtils.jwtProperties = new JwtProperties()
        alaWebServiceAuthUtils.jwtProperties.requireUserInfo = false

        CredentialsExtractor credentialsExtractor = Mock() {
            // extract the access_token
            1 * extract(_, _) >> Optional.of(new TokenCredentials('access_token'))
        }

        Authenticator userInfoOidcAuthenticator = Mock() {
            // validate the access_token
            1 * validate(_, _, _)
        }

        JwtAuthenticator jwtAuthenticator = Mock() {
            0 * validate(_, _, _)
        }

        alaWebServiceAuthUtils.config = new Config()
        alaWebServiceAuthUtils.config.sessionStore = Mock(SessionStore)
        alaWebServiceAuthUtils.directClient = new DirectBearerAuthClient()
        alaWebServiceAuthUtils.directClient.credentialsExtractor = credentialsExtractor
        alaWebServiceAuthUtils.directClient.authenticator = userInfoOidcAuthenticator
        alaWebServiceAuthUtils.jwtAuthenticator = jwtAuthenticator

        HttpServletRequest request = Mock(HttpServletRequest)
        HttpServletResponse response = Mock(HttpServletResponse)

        when:
        Optional<UserProfile> userProfile = alaWebServiceAuthUtils.oidcInterceptor(request, response)

        then:

        userProfile.isPresent()
        userProfile.get().attributes['email'] == 'email@test.com'
    }

    def 'validate required scopes'() {

        setup:
        AlaWebServiceAuthUtils alaWebServiceAuthUtils = new AlaWebServiceAuthUtils()

        JwtProperties jwtProperties = new JwtProperties()
        jwtProperties.requiredScopes = [ 'required:scope' ]

        alaWebServiceAuthUtils.jwtProperties = jwtProperties

        CredentialsExtractor credentialsExtractor = Mock() {
            1 * extract(_, _) >> {
                Credentials credentials = new TokenCredentials('access_token')
                credentials.userProfile = new OidcProfile()
                credentials.userProfile.addAttribute('email', 'email@test.com')
                Optional.of(credentials)
            }
        }

        JwtAuthenticator jwtAuthenticator = Mock() {
            1 * validate(_, _, _) >> { args ->
                Credentials credentials = args[0]
                credentials.userProfile = new OidcProfile()
                credentials.userProfile.addAttribute('scope', 'required:scope')
            }
        }

        alaWebServiceAuthUtils.config = new Config()
        alaWebServiceAuthUtils.config.sessionStore = Mock(SessionStore)
        alaWebServiceAuthUtils.directClient = new DirectBearerAuthClient()
        alaWebServiceAuthUtils.directClient.credentialsExtractor = credentialsExtractor
        alaWebServiceAuthUtils.directClient.authenticator = Mock(Authenticator)
        alaWebServiceAuthUtils.jwtAuthenticator = jwtAuthenticator
        alaWebServiceAuthUtils.attributeAuthorizationGenerator = new FromAttributesAuthorizationGenerator(jwtProperties.roleAttributes, jwtProperties.permissionAttributes)

        HttpServletRequest request = Mock(HttpServletRequest)
        HttpServletResponse response = Mock(HttpServletResponse)

        when:
        Optional<UserProfile> userProfile = alaWebServiceAuthUtils.oidcInterceptor(request, response)

        then:

        userProfile.isPresent()
        userProfile.get().attributes['email'] == 'email@test.com'
    }

    def 'missing required scopes'() {

        setup:
        AlaWebServiceAuthUtils alaWebServiceAuthUtils = new AlaWebServiceAuthUtils()

        JwtProperties jwtProperties = new JwtProperties()
        jwtProperties.requiredScopes = [ 'required:scope' ]

        alaWebServiceAuthUtils.jwtProperties = jwtProperties

        CredentialsExtractor credentialsExtractor = Mock() {
            1 * extract(_, _) >> {
                Credentials credentials = new TokenCredentials('access_token')
                credentials.userProfile = new OidcProfile()
                credentials.userProfile.addAttribute('email', 'email@test.com')
                Optional.of(credentials)
            }
        }

        JwtAuthenticator jwtAuthenticator = Mock() {
            1 * validate(_, _, _) >> { args ->
                Credentials credentials = args[0]
                credentials.userProfile = new OidcProfile()
            }
        }

        alaWebServiceAuthUtils.config = new Config()
        alaWebServiceAuthUtils.config.sessionStore = Mock(SessionStore)
        alaWebServiceAuthUtils.directClient = new DirectBearerAuthClient()
        alaWebServiceAuthUtils.directClient.credentialsExtractor = credentialsExtractor
        alaWebServiceAuthUtils.directClient.authenticator = Mock(Authenticator)
        alaWebServiceAuthUtils.jwtAuthenticator = jwtAuthenticator
        alaWebServiceAuthUtils.attributeAuthorizationGenerator = new FromAttributesAuthorizationGenerator(jwtProperties.roleAttributes, jwtProperties.permissionAttributes)

        HttpServletRequest request = Mock(HttpServletRequest)
        HttpServletResponse response = Mock(HttpServletResponse)

        when:
        alaWebServiceAuthUtils.oidcInterceptor(request, response)

        then:
        Exception ce = thrown CredentialsException
        ce.message == "access_token scopes '[]' is missing required scopes ${jwtProperties.requiredScopes}"
    }
}
