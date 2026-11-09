package au.org.ala.web


import grails.testing.web.interceptor.InterceptorUnitTest
import org.grails.web.util.GrailsApplicationAttributes
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

    Closure doWithConfig() {{ config ->
        config.custom.flags.disabled = true
        config.custom.flags.enabled = false
    }}

    void "Test sso interceptor matching"() {
        when:"A request matches the interceptor"
            withRequest(controller:"sso")

        then:"The interceptor does match"
            interceptor.doesMatch()
    }

    void "SSO can be disabled with a feature flag"() {
        setup:
        grailsApplication.addArtefact("Controller", SsoFeatureFlagController)
        interceptor.enabled = true
        interceptor.ssoStrategy = mockSsoStrategy

        when:
        request.setAttribute(GrailsApplicationAttributes.CONTROLLER_NAME_ATTRIBUTE, 'ssoFeatureFlag')
        request.setAttribute(GrailsApplicationAttributes.ACTION_NAME_ATTRIBUTE, action)
        withRequest(controller: "ssoFeatureFlag", action: action)
        def result = interceptor.before()

        then:
        calls * mockSsoStrategy.authenticate(_, _, false) >> false
        result == expected

        where:
        action         | calls | expected
        "flagDisabled" | 0     | true
        "flagEnabled"  | 1     | false
        "flagMissing"  | 1     | false
    }
}

class SsoFeatureFlagController {
    @SSO(disabledByFeatureFlag = 'custom.flags.disabled')
    def flagDisabled() {}

    @SSO(disabledByFeatureFlag = 'custom.flags.enabled')
    def flagEnabled() {}

    @SSO(disabledByFeatureFlag = 'custom.flags.missing')
    def flagMissing() {}
}
