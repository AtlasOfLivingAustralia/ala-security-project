package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import au.org.ala.ws.security.service.ApiKeyService
import grails.test.mixin.Mock
import grails.test.mixin.TestFor
import grails.test.mixin.TestMixin
import grails.test.mixin.support.GrailsUnitTestMixin
import grails.test.mixin.web.FiltersUnitTestMixin
import spock.lang.Specification
import spock.lang.Unroll


@TestFor(ApiKeyFilters)
@TestMixin([GrailsUnitTestMixin, FiltersUnitTestMixin])
@Unroll
@Mock([ApiKeyService])
class ApiKeyFiltersSpec extends Specification {

    static final int UNAUTHORISED = 403
    static final int OK = 200

    void setup() {
        // grailsApplication is not isolated in unit tests, so clear the ip.whitelist property to avoid polluting independent tests
        grailsApplication.config.security.apikey.ip = [whitelist: ""]
    }

    void "All methods of a controller annotated with RequireApiKey at the class level should be protected"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        request.addHeader("apiKey", "invalid")

        withFilters(controller: "annotatedClass", action: action) {
            controller."${action}"()
        }

        then:
        response.status == responseCode

        where:
        action    | responseCode
        "action1" | UNAUTHORISED
        "action2" | UNAUTHORISED
    }

    void "Only methods annotated with RequireApiKey should be protected if the class is not annotated"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedMethodController)

        AnnotatedMethodController controller = new AnnotatedMethodController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        request.addHeader("apiKey", "invalid")

        withFilters(controller: "annotatedMethod", action: action) {
            controller."${action}"()
        }

        then:
        response.status == responseCode

        where:
        action          | responseCode
        "securedAction" | UNAUTHORISED
        "publicAction"  | OK
    }

    void "Methods annotated with SkipApiKeyCheck should be accessible even when the class is annotated with RequireApiKey"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        request.addHeader("apiKey", "invalid")

        withFilters(controller: "annotatedClass", action: "action3") {
            controller.action3()
        }

        then:
        response.status == OK

    }

    void "Secured methods should be accessible when given a valid key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        request.addHeader("apiKey", "valid")

        withFilters(controller: "annotatedClass", action: action) {
            controller."${action}"()
        }

        then:
        response.status == responseCode

        where:
        action    | responseCode
        "action1" | OK
        "action2" | OK
    }

    void "Secured methods should be accessible when the request is from an IP on the whitelist, even with no API Key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        grailsApplication.config.security.apikey.ip = [whitelist: "2.2.2.2, 3.3.3.3"]
        request.remoteHost = ipAddress

        withFilters(controller: "annotatedClass", action: action) {
            controller."${action}"()
        }

        then:
        response.status == responseCode

        where:
        ipAddress | action    | responseCode
        "2.2.2.2" | "action1" | OK
        "3.3.3.3" | "action2" | OK
        "6.6.6.6" | "action2" | UNAUTHORISED
    }

    void "Secured methods should be accessible when the request is from the loopback IP Address, even with no API Key"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        request.remoteHost = ipAddress

        withFilters(controller: "annotatedClass", action: action) {
            controller."${action}"()
        }

        then:
        response.status == responseCode

        where:
        ipAddress         | action    | responseCode
        "127.0.0.1"       | "action1" | OK
        "::1"             | "action2" | OK
        "0:0:0:0:0:0:0:1" | "action2" | OK
        "1.2.3.4"         | "action2" | UNAUTHORISED
    }

    void "Do not trust the X-Forwarded-For header when it is attempting to use the loopback addresses (easily faked)"() {
        setup:
        // need to do this because grailsApplication.controllerClasses is empty in the filter when run from the unit test
        // unless we manually add the dummy controller class used in this test
        grailsApplication.addArtefact("Controller", AnnotatedClassController)

        AnnotatedClassController controller = new AnnotatedClassController()

        defineBeans {
            apiKeyService(MockApiKeyService)
        }

        when:
        request.addHeader("X-Forwarded-For", ipAddress)
        request.remoteHost = "1.2.3.4"

        withFilters(controller: "annotatedClass", action: action) {
            controller."${action}"()
        }

        then:
        response.status == responseCode

        where:
        ipAddress         | action    | responseCode
        "127.0.0.1"       | "action1" | UNAUTHORISED
        "::1"             | "action2" | UNAUTHORISED
        "0:0:0:0:0:0:0:1" | "action2" | UNAUTHORISED
        "1.2.3.4"         | "action2" | UNAUTHORISED
    }
}

@RequireApiKey
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

class MockApiKeyService extends ApiKeyService {

    @Override
    Map checkApiKey(String key) {
        return [valid: (key == "valid")]
    }
}

