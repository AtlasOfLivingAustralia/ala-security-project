package au.org.ala.web


import grails.testing.web.interceptor.InterceptorUnitTest
import org.grails.spring.beans.factory.InstanceFactoryBean
import org.apereo.cas.client.authentication.DefaultGatewayResolverImpl
import spock.lang.Specification

/**
 * Interceptor unit test coverage for the SSO interceptor.
 */
class SsoInterceptorSpec extends Specification implements InterceptorUnitTest<SsoInterceptor> {

    SSOStrategy mockSsoStrategy = Mock(SSOStrategy)
    CoreAuthProperties coreAuthProperties = new CoreAuthProperties()
    CasClientProperties casClientProperties = new CasClientProperties()

    def setup() {
        defineBeans {
            ssoStrategy(InstanceFactoryBean, mockSsoStrategy, SSOStrategy)
            coreAuthProperties(InstanceFactoryBean, coreAuthProperties, CoreAuthProperties)
            casClientProperties(InstanceFactoryBean, casClientProperties, CasClientProperties)
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
