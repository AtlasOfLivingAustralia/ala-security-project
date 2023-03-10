package au.org.ala.web


import grails.testing.web.interceptor.InterceptorUnitTest
import org.grails.spring.beans.factory.InstanceFactoryBean
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl
import spock.lang.Specification

/**
 * See the API for {@link grails.test.mixin.web.ControllerUnitTestMixin} for usage instructions
 */
class SsoInterceptorSpec extends Specification implements InterceptorUnitTest<SsoInterceptor> {

    SSOStrategy mockSsoStrategy = Mock(SSOStrategy)

    def setup() {
        defineBeans{
            ssoStrategy(InstanceFactoryBean, mockSsoStrategy, SSOStrategy)
        }
    }

    def cleanup() {

    }

    Closure doWithSpring() {{ ->
        ignoreUrlPatternMatcherStrategy(RegexListUrlPatternMatcherStrategy)
        userAgentFilterService(UserAgentFilterService, null, [])
        gatewayStorage(DefaultGatewayResolverImpl)
//        grailsApplication(grailsApplication)
    }}

    void "Test sso interceptor matching"() {
        when:"A request matches the interceptor"
            withRequest(controller:"sso")

        then:"The interceptor does match"
            interceptor.doesMatch()
    }
}
