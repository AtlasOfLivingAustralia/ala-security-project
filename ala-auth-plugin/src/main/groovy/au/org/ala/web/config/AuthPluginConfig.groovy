package au.org.ala.web.config

import au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter
import au.org.ala.cas.client.UriFilter
import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.web.CasContextParamInitializer
import au.org.ala.web.UriExclusionFilter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Rfc3339DateJsonAdapter
import grails.core.GrailsApplication
import grails.util.Metadata
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import okhttp3.OkHttpClient
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.util.AntPathMatcher

import javax.servlet.DispatcherType
import javax.servlet.Filter

import static java.util.concurrent.TimeUnit.MILLISECONDS

@CompileStatic
@Configuration("alaAuthPluginConfiguration")
@Slf4j
class AuthPluginConfig {

    @Autowired
    GrailsApplication grailsApplication

    @ConditionalOnMissingBean(name = "userDetailsHttpClient")
    @Bean(name = ["defaultUserDetailsHttpClient", "userDetailsHttpClient"])
    OkHttpClient userDetailsHttpClient(GrailsApplication grailsApplication) {
        Integer readTimeout = grailsApplication.config['userDetails']['readTimeout'] as Integer
        new OkHttpClient.Builder().readTimeout(readTimeout, MILLISECONDS).build()
    }

    @ConditionalOnMissingBean(name = "userDetailsMoshi")
    @Bean(name = ["defaultUserDetailsMoshi", "userDetailsMoshi"])
    Moshi userDetailsMoshi() {
        new Moshi.Builder().add(Date, new Rfc3339DateJsonAdapter().nullSafe()).build()
    }


    @Bean("userDetailsClient")
    UserDetailsClient userDetailsClient(@Qualifier("userDetailsHttpClient") OkHttpClient userDetailsHttpClient,
                                        @Qualifier('userDetailsMoshi') Moshi moshi,
                                        GrailsApplication grailsApplication) {
        String baseUrl = grailsApplication.config["userDetails"]["url"]
        new UserDetailsClient.Builder(userDetailsHttpClient, baseUrl).moshi(moshi).build()
    }

    @Bean
    CasContextParamInitializer casContextParamInitializer() {
        new CasContextParamInitializer()
    }

    // The filter chain has to be before grailsWebRequestFilter but after the encoding filter.
    // Its order changed in 3.1 (from Ordered.HIGHEST_PRECEDENCE + 30 (-2147483618) to
    // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 30 (30))
    private static int filterOrder() {
        final filterOrder
        String grailsVersion = Metadata.current.getGrailsVersion()
        if (grailsVersion.startsWith('3.0')) {
            filterOrder = Ordered.HIGHEST_PRECEDENCE + 21
        }
        else {
            filterOrder = 21 // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
        }
        return filterOrder
    }

    @Bean
    FilterRegistrationBean casSSOFilter() {
        new FilterRegistrationBean().with {
            name = 'Cas Single Sign Out Filter'
            filter = new SingleSignOutFilter()
            dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
            order = filterOrder()
            urlPatterns = ['/*']
            asyncSupported = true
            it
        }
    }
    @Bean
    FilterRegistrationBean casAuthFilter() {
        new FilterRegistrationBean().with {
            name = 'CAS Authentication Filter'
            filter = new UriFilter()
            dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
            order = filterOrder() + 1
            urlPatterns = ['/*']
            asyncSupported = true
            initParameters = [
                    'filterClass': AuthenticationFilter.name,
                    'disableCAS': grailsApplication.config.getProperty('security.cas.bypass', Boolean, false).toString()
            ]
            it
        }
    }

    @Bean
    FilterRegistrationBean casValidationFilter() {
        new FilterRegistrationBean().with {
            name = 'CAS Validation Filter'
            filter = new UriFilter()
            dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
            order = filterOrder() + 2
            urlPatterns = ['/*']
            asyncSupported = true
            initParameters = [
                    'filterClass': Cas30ProxyReceivingTicketValidationFilter.name,
                    'disableCAS': grailsApplication.config.getProperty('security.cas.bypass', Boolean, false).toString()
            ]
            it
        }
    }

    @Bean
    FilterRegistrationBean casHttpServletRequestWrapperFilter() {
        new FilterRegistrationBean().with {
            name = 'CAS HttpServletRequest Wrapper Filter'
            filter = wrapFilterForActuator(new AlaHttpServletRequestWrapperFilter())
            dispatcherTypes = EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR)
            order = filterOrder() + 3
            urlPatterns = ['/*']
            asyncSupported = true
            initParameters = [:]
            it
        }
    }

    private Filter wrapFilterForActuator(Filter delegate) {
        final filter
        final config = grailsApplication.config
        final managementSecurityEnabled = config.getProperty('management.security.enabled', Boolean, false)
        final springSecurityBasicEnabled = config.getProperty('security.basic.enabled', Boolean, false)
        if (managementSecurityEnabled && springSecurityBasicEnabled) {
            final matcher = new AntPathMatcher()
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
