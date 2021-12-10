package au.org.ala.ws.security

import au.org.ala.ws.security.RequireAuth
import au.org.ala.ws.security.SkipAuthCheck

import grails.testing.web.interceptor.InterceptorUnitTest
import org.grails.web.util.GrailsApplicationAttributes
import spock.lang.Specification

class AlaAuthInterceptorSpec extends Specification implements InterceptorUnitTest<AlaAuthInterceptor> {

    static final int UNAUTHORISED = 403
    static final int OK = 200

    def setup() {
    }

    def cleanup() {

    }

    void "All methods of a controller annotated with RequireAuth at the class level should be protected"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", DummyController)
        DummyController controller = new DummyController()

        when:
        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'dummy')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: controller, action: action)
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
        request.setUserPrincipal(null)
        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'annotatedMethod')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: controller, action: action)
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
}