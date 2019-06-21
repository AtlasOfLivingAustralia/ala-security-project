package au.org.ala.web


import grails.test.mixin.TestFor
import spock.lang.Specification

/**
 * See the API for {@link grails.test.mixin.web.ControllerUnitTestMixin} for usage instructions
 */
@TestFor(SsoInterceptor)
class SsoInterceptorSpec extends Specification {

    def setup() {
    }

    def cleanup() {

    }

    void "Test sso interceptor matching"() {
        when:"A request matches the interceptor"
            withRequest(controller:"sso")

        then:"The interceptor does match"
            interceptor.doesMatch()
    }
}
