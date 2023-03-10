package au.org.ala.web.config

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.web.CasAuthService
import au.org.ala.web.CasClientProperties
import au.org.ala.web.CasContextParamInitializer
import au.org.ala.web.CasSSOStrategy
import au.org.ala.web.CookieFilterWrapper
import au.org.ala.web.CooperatingFilterWrapper
import au.org.ala.web.CoreAuthProperties
import au.org.ala.web.IAuthService
import au.org.ala.web.RegexListUrlPatternMatcherStrategy
import au.org.ala.web.SSOStrategy
import au.org.ala.web.UriExclusionFilter
import au.org.ala.web.UserAgentBypassFilterWrapper
import au.org.ala.web.UserAgentFilterService
import grails.core.GrailsApplication
import grails.util.Metadata
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl
import org.jasig.cas.client.authentication.GatewayResolver
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy
import org.jasig.cas.client.configuration.ConfigurationKeys
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.util.AntPathMatcher

import javax.servlet.DispatcherType
import javax.servlet.Filter

@CompileStatic
@Configuration("alaAuthPluginConfiguration")
@EnableConfigurationProperties([CasClientProperties, CoreAuthProperties])
@Slf4j
class AuthPluginConfig {

    static final String AUTH_FILTER_KEY = '_cas_authentication_filter_'

    @Autowired
    CasClientProperties casClientProperties
    @Autowired
    CoreAuthProperties coreAuthProperties

    @Autowired
    GrailsApplication grailsApplication

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    IAuthService delegateService(UserDetailsClient userDetailsClient) {
        new CasAuthService(userDetailsClient, casClientProperties.bypass, casClientProperties.loginUrl)
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    CasContextParamInitializer casContextParamInitializer() {
        new CasContextParamInitializer(coreAuthProperties, casClientProperties)
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean("ignoreUrlPatternMatcherStrategy")
    UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategy() {
        def strat = new RegexListUrlPatternMatcherStrategy()
        strat.setPattern((coreAuthProperties.uriExclusionFilterPattern + casClientProperties.uriExclusionFilterPattern).join(','))
        return strat
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @ConditionalOnMissingBean(name = 'gatewayResolver')
    @Bean('gatewayResolver')
    GatewayResolver gatewayResolver() {
        final GatewayResolver resolver
        if (casClientProperties.gatewayStorageClass) {
            resolver = (GatewayResolver) Class.forName(casClientProperties.gatewayStorageClass).newInstance()
        } else {
            resolver = new DefaultGatewayResolverImpl()
        }
        return resolver
    }

    // The filter chain has to be before grailsWebRequestFilter but after the encoding filter.
    // Its order changed in 3.1 (from Ordered.HIGHEST_PRECEDENCE + 30 (-2147483618) to
    // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 30 (30))
    static int filterOrder() {
        String grailsVersion = Metadata.current.getGrailsVersion()
        if (grailsVersion.startsWith('3.0')) {
            return Ordered.HIGHEST_PRECEDENCE + 21
        }
        else {
            return 21 // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
        }
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casSSOFilter() {
        def frb = new FilterRegistrationBean()
        frb.name = 'Cas Single Sign Out Filter'
        frb.filter = new SingleSignOutFilter()
        frb.setDispatcherTypes(EnumSet.of(DispatcherType.REQUEST))
        frb.setOrder(filterOrder())
        frb.setUrlPatterns(['/*'])
        frb.setAsyncSupported(true)
        return frb
    }

    private static void logFilter(String name, FilterRegistrationBean frb) {
        if (frb.enabled) {
            log.debug('{} enabled with type: {}', name, frb.filter)
            log.debug('{} enabled with params: {}', name, frb.initParameters)
            log.debug('{} enabled for paths: {}', name, frb.urlPatterns)
        } else {
            log.debug('{} disabled', name)
        }
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casAuthFilter() {
        final name = 'CAS Authentication Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        frb.filter = new CooperatingFilterWrapper(new AuthenticationFilter(), AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 1
        frb.urlPatterns = coreAuthProperties.uriFilterPattern ?: casClientProperties.uriFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'false']
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casAuthGatewayFilter(UserAgentFilterService userAgentFilterService) {
        final name = 'CAS Gateway Authentication Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        frb.filter = new CooperatingFilterWrapper(new UserAgentBypassFilterWrapper(new AuthenticationFilter(), userAgentFilterService), AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 2
        frb.urlPatterns =  casClientProperties.gatewayFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'true']
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casAuthCookieFilter() {
        final name = 'CAS Cookie Authentication Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        frb.filter = new CooperatingFilterWrapper(new CookieFilterWrapper(new AuthenticationFilter(), coreAuthProperties.authCookieName ?: casClientProperties.authCookieName), AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 3
        frb.urlPatterns = coreAuthProperties.optionalFilterPattern +
                casClientProperties.authenticateOnlyIfCookieFilterPattern +
                casClientProperties.authenticateOnlyIfLoggedInPattern +
                casClientProperties.authenticateOnlyIfLoggedInFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'false']
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casAuthCookieGatewayFilter(UserAgentFilterService userAgentFilterService) {
        final name = 'CAS Gateway Cookie Authentication Filter'
        def frb = new FilterRegistrationBean()
        frb.name = name
        frb.filter = new CooperatingFilterWrapper(new CookieFilterWrapper(new UserAgentBypassFilterWrapper(new AuthenticationFilter(), userAgentFilterService), coreAuthProperties.authCookieName ?: casClientProperties.authCookieName), AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 4
        frb.urlPatterns = casClientProperties.gatewayIfCookieFilterPattern
        frb.enabled = !frb.urlPatterns.empty
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'true']
        logFilter(name, frb)
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casValidationFilter() {
        def frb = new FilterRegistrationBean()
        frb.name = 'CAS Validation Filter'
        frb.filter = new Cas30ProxyReceivingTicketValidationFilter()
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 5
        frb.urlPatterns = ['/*']
        frb.asyncSupported = true
        frb.initParameters = [:]
        log.debug('CAS Validation Filter enabled')
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casHttpServletRequestWrapperFilter() {
        FilterRegistrationBean frb = new FilterRegistrationBean()
        frb.name = 'CAS HttpServletRequest Wrapper Filter'
        frb.filter = wrapFilterForActuator(new HttpServletRequestWrapperFilter())
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR)
        frb.order = filterOrder() + 6
        frb.urlPatterns = ['/*']
        frb.asyncSupported = true
        frb.initParameters = [:]
        log.debug('CAS HttpServletRequest Wrapper Filter enabled')
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    SSOStrategy ssoStrategy(UserAgentFilterService userAgentFilterService) {
        new CasSSOStrategy(
                casClientProperties.service,
                casClientProperties.appServerName,
                casClientProperties.loginUrl,
                coreAuthProperties.authCookieName ?: casClientProperties.authCookieName,
                casClientProperties.encodeServiceUrl,
                casClientProperties.enabled,
                casClientProperties.renew,
                ignoreUrlPatternMatcherStrategy(),
                userAgentFilterService,
                gatewayResolver()
        )
    }

    // nb this would be nicer if we could use the Spring Boot Configuration Property classes but these seem to cause
    // problems for grails.
    private Filter wrapFilterForActuator(Filter delegate) {
        final filter
        final config = grailsApplication.config
        final managementSecurityEnabled = config.getProperty('management.security.enabled', Boolean, false)
        final springSecurityBasicEnabled = config.getProperty('security.basic.enabled', Boolean, false)
        if (managementSecurityEnabled && springSecurityBasicEnabled) {
            AntPathMatcher matcher = new AntPathMatcher()
            final path = config.getProperty('management.contextPath') ?: config.getProperty('management.context-path', '')
            if (path) {
                final basicPaths = config.getProperty('security.basic.path', String[])
                final matches = basicPaths?.any { String pattern -> matcher.match(pattern, path) }
                if (matches) {
                    log.info('Wrapping {} because {} is in {}', delegate, path, basicPaths)
                    filter = new UriExclusionFilter(delegate, path)
                } else {
                    log.info('Not wrapping {} because the management path {} isn\'t covered by the basic auth paths {}', delegate, path, basicPaths)
                    filter = delegate
                }
            } else {
                log.info('Not wrapping {} because the management path is not set', delegate)
                filter = delegate
            }
        } else {
            log.info('Not wrapping {} because either management security ({}) or spring security basic auth ({}) is not enabled', delegate, managementSecurityEnabled, springSecurityBasicEnabled)
            filter = delegate
        }
        return filter
    }

}
