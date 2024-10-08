package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.ala.org.ws.security.filter.RequireApiKeyFilter
import au.org.ala.ws.security.authenticator.AlaApiKeyAuthenticator
import au.org.ala.ws.security.authenticator.AlaIpWhitelistAuthenticator
import au.org.ala.ws.security.authenticator.AlaOidcAuthenticator
import au.org.ala.ws.security.client.AlaApiKeyClient
import au.org.ala.ws.security.client.AlaAuthClient
import au.org.ala.ws.security.client.AlaIpWhitelistClient
import au.org.ala.ws.security.client.AlaOidcClient
import au.org.ala.ws.security.credentials.AlaApiKeyCredentialsExtractor
import au.org.ala.ws.security.credentials.AlaOidcCredentialsExtractor
import au.org.ala.ws.security.profile.AlaApiUserProfile

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.RemoteJWKSet
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.oauth2.sdk.id.Issuer
import grails.testing.web.interceptor.InterceptorUnitTest
import grails.web.api.ServletAttributes
import groovy.time.TimeCategory
import org.grails.spring.beans.factory.InstanceFactoryBean
import org.grails.web.util.GrailsApplicationAttributes
import org.pac4j.core.config.Config
import org.pac4j.core.exception.CredentialsException
import org.pac4j.core.profile.creator.ProfileCreator
import org.pac4j.http.credentials.extractor.IpExtractor
import org.pac4j.jee.context.session.JEESessionStore
import org.pac4j.oidc.config.OidcConfiguration
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll

import static au.org.ala.ws.security.JwtUtils.*

@Unroll
class AlaSecurityInterceptorSpec extends Specification implements InterceptorUnitTest<AlaSecurityInterceptor> {

    static final int UNAUTHORISED = 401
    static final int FORBIDDEN = 403
    static final int OK = 200

    JWKSet jwkSet = jwkSet('test.jwks')
    def jwtProperties = new JwtProperties()

    @Shared
    AlaOidcClient alaOidcClient

    @Shared
    AlaApiKeyClient alaApiKeyClient

    @Shared
    AlaIpWhitelistClient alaIpWhitelistClient
    void setup() {

        OidcConfiguration oidcConfiguration = Mock()

        GroovyMock(RemoteJWKSet, global: true)
        new RemoteJWKSet(_, _) >> new ImmutableJWKSet<SecurityContext>(jwkSet('test.jwks'))

        ProfileCreator profileCreator = Mock()

        AlaOidcAuthenticator alaOidcAuthenticator = new AlaOidcAuthenticator(oidcConfiguration, profileCreator)
        alaOidcAuthenticator.issuer = new Issuer('http://localhost')
        alaOidcAuthenticator.expectedJWSAlgs = [ JWSAlgorithm.RS256 ].toSet()
        alaOidcAuthenticator.requiredClaims = []
        alaOidcAuthenticator.keySource = new ImmutableJWKSet<SecurityContext>(jwkSet)

        AlaApiKeyAuthenticator alaApiKeyAuthenticator = Stub(AlaApiKeyAuthenticator) {
            validate(_, _, _) >> { args ->
                if (args[0].token == 'valid') {
                    args[0].userProfile = new AlaApiUserProfile(email: 'email@test.com', givenName: 'first_name', familyName: 'last_name')
                } else {
                    throw new CredentialsException("invalid apikey: '${args[0].token}'")
                }
            }
        }

        AlaIpWhitelistAuthenticator alaIpWhitelistAuthenticator = new AlaIpWhitelistAuthenticator()
        alaIpWhitelistAuthenticator.ipWhitelist = [ '2.2.2.2', '3.3.3.3' ]

        alaOidcClient = new AlaOidcClient(new AlaOidcCredentialsExtractor(), alaOidcAuthenticator)
        alaApiKeyClient = new AlaApiKeyClient(new AlaApiKeyCredentialsExtractor(), alaApiKeyAuthenticator)
        alaIpWhitelistClient = new AlaIpWhitelistClient(new IpExtractor(), alaIpWhitelistAuthenticator)

        defineBeans {
            config(InstanceFactoryBean, new Config().tap { sessionStore = JEESessionStore.INSTANCE })
            alaAuthClient(InstanceFactoryBean, new AlaAuthClient().tap {

                it.authClients = [ alaOidcClient, alaApiKeyClient, alaIpWhitelistClient ]
            })

            jwtProperties(InstanceFactoryBean, jwtProperties)

            requireApiKeyFilter(InstanceFactoryBean, new RequireApiKeyFilter() {

                @Override
                boolean isAllowed(RequireApiKey annotation, ServletAttributes servletAttributes) {
                    return servletAttributes.actionName == 'action1'
                }
            })
        }

    }

    Closure doWithConfig() {{ config ->
        config.custom.app.scopes = ['read:userdetails']
        config.custom.app.scopes2 = []
    }}

    void "All methods of a controller annotated with RequireApiKey at the class level should be protected"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("apiKey", "invalid")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
//        1 * alaAuthClient.getCredentials(_, _) >> Optional.empty()

        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | UNAUTHORISED | false
        "action2" | UNAUTHORISED | false
    }

    void "Only methods annotated with RequireApiKey should be protected if the class is not annotated"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedMethodController)

        AlaApiKeyAuthenticator alaApiKeyAuthenticator = Spy()
        AlaApiKeyClient apiKeyClient = new AlaApiKeyClient(new AlaApiKeyCredentialsExtractor(), alaApiKeyAuthenticator)
        interceptor.alaAuthClient = new AlaAuthClient()
        interceptor.alaAuthClient.authClients = [ apiKeyClient ]

        AnnotatedMethodController controller = new AnnotatedMethodController()

        when:
        request.addHeader("apiKey", "invalid")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedMethod')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedMethod", action: action)
        def result = interceptor.before()

        then:
        alaApiKeyAuthenticator.validate(_, _, _) >> { throw new CredentialsException('invalid apikey')}
        result == before
        response.status == responseCode

        where:
        action          | responseCode | before
        "securedAction" | UNAUTHORISED | false
        "publicAction"  | OK           | true
    }

    void "Methods annotated with SkipApiKeyCheck should be accessible even when the class is annotated with RequireApiKey"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("apiKey", "invalid")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, 'action3')
        withRequest(controller: "annotatedClass", action: "action3")
        def result = interceptor.before()

        then:
        result == true
        response.status == OK

    }

    void "Secured methods should be accessible when given a valid key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("apiKey", "valid")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | OK           | true
        "action2" | OK           | true
    }

    void "Secured methods should be accessible when given a valid key in the alternate headers"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        alaApiKeyClient.credentialsExtractor.alternativeHeaderNames = [ 'Authorization' ]
//        grailsApplication.config.security.apikey.header.alternatives = [ 'Authorization' ]

        when:
        request.addHeader("Authorization", "valid")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | OK           | true
        "action2" | OK           | true
    }

    void "Secured methods should be accessible when the request is from an IP on the whitelist, even with no API Key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.remoteAddr = ipAddress

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        ipAddress | action    | responseCode | before
        "2.2.2.2" | "action1" | OK           | true
        "3.3.3.3" | "action2" | OK           | true
        "6.6.6.6" | "action2" | UNAUTHORISED | false
    }

    void "Secured methods should be accessible when the request is from the loopback IP Address, even with no API Key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.remoteAddr = ipAddress

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        ipAddress         | action    | responseCode | before
        "127.0.0.1"       | "action1" | OK           | true
        "::1"             | "action2" | OK           | true
        "0:0:0:0:0:0:0:1" | "action2" | OK           | true
        "1.2.3.4"         | "action2" | UNAUTHORISED | false
    }

    void "Do not trust the X-Forwarded-For header when it is attempting to use the loopback addresses (easily faked)"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("X-Forwarded-For", ipAddress)
        request.remoteAddr = "1.2.3.4"

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        ipAddress         | action    | responseCode | before
        "127.0.0.1"       | "action1" | UNAUTHORISED | false
        "::1"             | "action2" | UNAUTHORISED | false
        "0:0:0:0:0:0:0:1" | "action2" | UNAUTHORISED | false
        "1.2.3.4"         | "action2" | UNAUTHORISED | false
    }

    void "Secured methods should be accessible when given a valid JWT"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("Authorization", "Bearer ${generateJwt(jwkSet)}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | OK           | true
        "action2" | OK           | true
    }

    void "Secured methods should be accessible when given a valid JWT and the required scopes are from a a configuration property"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClass2Controller)

        AnnotatedClass2Controller controller = new AnnotatedClass2Controller()

        when:
        request.addHeader("Authorization", "Bearer ${generateJwt(jwkSet, ['app/scope', 'read:userdetails'].toSet())}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass2')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass2", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | OK           | true
        "action2" | OK           | true
    }

    void "Secured methods should be accessible when given a valid JWT and a custom authorisation filter is applied"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClass3Controller)

        AnnotatedClass3Controller controller = new AnnotatedClass3Controller()

        when:
        request.addHeader("Authorization", "Bearer ${generateJwt(jwkSet)}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass3')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass3", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | OK           | true
        "action2" | FORBIDDEN    | false
    }

    void "Secured methods should be inaccessible when given a valid JWT without the required scopes"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("Authorization", "Bearer ${generateJwt(jwkSet, ['openid'].toSet())}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | FORBIDDEN | false
        "action2" | FORBIDDEN | false
    }

    void "Secured methods should be inaccessible when given a valid JWT without the required scopes from properties"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        alaOidcClient.authenticator.requiredScopes = [ 'missing' ]

        when:
        request.addHeader("Authorization", "Bearer ${generateJwt(jwkSet)}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | UNAUTHORISED | false
        "action2" | UNAUTHORISED | false
    }

    void "Secured methods should be inaccessible when given a valid JWT signed with the wrong key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        when:
        request.addHeader("Authorization", "Bearer ${generateJwt(jwkSet('wrong-test.jwks'))}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | UNAUTHORISED | false
        "action2" | UNAUTHORISED | false
    }

    void "Secured methods should be inaccessible with a JWT issued by the wrong issuer"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        def jwt = generateJwt(jwkSet, generateClaims(['read:userdetails'].toSet()).issuer('http://example.org').build())

        when:
        request.addHeader("Authorization", "Bearer ${jwt}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | UNAUTHORISED | false
        "action2" | UNAUTHORISED | false
    }

    void "Secured methods should be inaccessible with an expired JWT"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        def jwt = generateJwt(jwkSet,
                generateClaims(['read:userdetails'].toSet()).expirationTime(use(TimeCategory) { new Date() - 1.day }).build())

        when:
        request.addHeader("Authorization", "Bearer ${jwt}")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedClass')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedClass", action: action)
        def result = interceptor.before()

        then:
        result == before
        response.status == responseCode

        where:
        action    | responseCode | before
        "action1" | UNAUTHORISED | false
        "action2" | UNAUTHORISED | false
    }


}

@RequireApiKey(scopes=['read:userdetails'], scopesFromProperty = ['custom.app.scopes2'])
class AnnotatedClassController {
    def action1() {

    }

    def action2() {

    }

    @SkipApiKeyCheck
    def action3() {

    }
}

@RequireApiKey(scopes=['app/scope'], scopesFromProperty = ['custom.app.scopes'])
class AnnotatedClass2Controller {
    def action1() {

    }

    def action2() {

    }

    @SkipApiKeyCheck
    def action3() {

    }
}

@RequireApiKey(scopes=['read:userdetails'], useCustomFilter = true)
class AnnotatedClass3Controller {
    def action1() {

    }

    def action2() {

    }

    @SkipApiKeyCheck
    def action3() {

    }
}


class AnnotatedMethodController {
    @RequireApiKey
    def securedAction() {

    }

    def publicAction() {

    }
}
