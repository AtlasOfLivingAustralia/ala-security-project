package au.org.ala.web


import grails.test.mixin.TestFor
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl
import org.jasig.cas.client.authentication.GatewayResolver
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy
import org.springframework.beans.factory.annotation.Autowired
import spock.lang.Specification

/**
 * See the API for {@link grails.test.mixin.web.ControllerUnitTestMixin} for usage instructions
 */
@TestFor(SsoInterceptor)
class SsoInterceptorSpec extends Specification {

    def setup() {
        defineBeans(true) {
            grailsApplication(grailsApplication)
        }
    }

    def cleanup() {

    }

    def doWithSpring = {
        ignoreUrlPatternMatcherStrategy(RegexListUrlPatternMatcherStrategy)
        userAgentFilterService(UserAgentFilterService, null, [])
        gatewayStorage(DefaultGatewayResolverImpl)
        grailsApplication(grailsApplication)
    }

    void "Test sso interceptor matching"() {
        when:"A request matches the interceptor"
            withRequest(controller:"sso")

        then:"The interceptor does match"
            interceptor.doesMatch()
    }
}
