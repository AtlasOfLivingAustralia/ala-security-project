package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.ws.security.service.ApiKeyService
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.SecurityContext
import grails.testing.web.interceptor.InterceptorUnitTest
import groovy.time.TimeCategory
import org.grails.spring.beans.factory.InstanceFactoryBean
import org.grails.web.util.GrailsApplicationAttributes
import org.pac4j.core.authorization.generator.FromAttributesAuthorizationGenerator
import org.pac4j.core.config.Config
import org.pac4j.http.client.direct.DirectBearerAuthClient
import org.pac4j.jee.context.session.JEESessionStore
import spock.lang.Specification
import spock.lang.Unroll

import static au.org.ala.ws.security.JwtUtils.*

@Unroll
class ApiKeyInterceptorSpec extends Specification implements InterceptorUnitTest<ApiKeyInterceptor> {

    static final int UNAUTHORISED = 403
    static final int OK = 200

    ApiKeyService apiKeyService

    JWKSet jwkSet = jwkSet('test.jwks')
    def jwtProperties = new JwtProperties()

    void setup() {

        defineBeans {
            config(InstanceFactoryBean, new Config().tap { sessionStore = JEESessionStore.INSTANCE })
            directBearerAuthClient(InstanceFactoryBean,
                    new DirectBearerAuthClient(
                            new JwtAuthenticator(
                                    'http://localhost',
                                    jwtProperties.getRequiredClaims(),
                                    [JWSAlgorithm.RS256].toSet(),
                                    new ImmutableJWKSet<SecurityContext>(jwkSet))
                    ).tap {
                        it.addAuthorizationGenerator(new FromAttributesAuthorizationGenerator(['role'],['scope', 'scp']))
                    })
            jwtProperties(InstanceFactoryBean, jwtProperties)
        }

        // grailsApplication is not isolated in unit tests, so clear the ip.whitelist property to avoid polluting independent tests
        grailsApplication.config.security.apikey.ip = [whitelist: ""]
        apiKeyService = Stub(ApiKeyService)
        apiKeyService.checkApiKey(_) >> { String key -> [valid: (key == "valid")] }

        interceptor.apiKeyService = apiKeyService
    }

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

        AnnotatedMethodController controller = new AnnotatedMethodController()

        when:
        request.addHeader("apiKey", "invalid")

        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedMethod')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "annotatedMethod", action: action)
        def result = interceptor.before()

        then:
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
        grailsApplication.config.security.apikey.header.alternatives = ['Authorization']

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
        grailsApplication.config.security.apikey.ip = [whitelist: "2.2.2.2, 3.3.3.3"]
        request.remoteHost = ipAddress

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
        request.remoteHost = ipAddress

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
        request.remoteHost = "1.2.3.4"

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
        "action1" | UNAUTHORISED | false
        "action2" | UNAUTHORISED | false
    }

    void "Secured methods should be inaccessible when given a valid JWT without the required scopes from properties"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()
        interceptor.jwtProperties.requiredScopes += 'missing'

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

@RequireApiKey(scopes=['read:userdetails'])
class AnnotatedClassController {
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
