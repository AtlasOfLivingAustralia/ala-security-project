package au.org.ala.web.config

import au.org.ala.userdetails.UserDetailsClient
import au.org.ala.web.CasClientProperties
import au.org.ala.web.CasContextParamInitializer
import au.org.ala.web.CooperatingFilterWrapper
import au.org.ala.web.UserAgentBypassFilterWrapper
import com.squareup.moshi.Moshi
import com.squareup.moshi.Rfc3339DateJsonAdapter
import grails.core.GrailsApplication
import grails.util.Metadata
import groovy.transform.CompileStatic
import okhttp3.OkHttpClient
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.configuration.ConfigurationKeys
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered

import javax.servlet.DispatcherType

import static java.util.concurrent.TimeUnit.MILLISECONDS

@CompileStatic
@Configuration("alaAuthPluginConfiguration")
@EnableConfigurationProperties(CasClientProperties)
class AuthPluginConfig {

    static final String AUTH_FILTER_KEY = '_cas_authentication_filter_'
    static final String VALIDATION_FILTER_KEY = '_cas_validation_filter_'

    @Autowired
    CasClientProperties casClientProperties

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
        new CasContextParamInitializer(casClientProperties)
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

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casAuthFilter() {
        def frb = new FilterRegistrationBean()
        frb.name = 'CAS Authentication Filter'
        frb.filter = new CooperatingFilterWrapper(new AuthenticationFilter(), AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 1
        frb.urlPatterns = casClientProperties.uriFilterPattern
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'false']
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casAuthGatewayFilter() {
        def frb = new FilterRegistrationBean()
        frb.name = 'CAS Gateway Authentication Filter'
        frb.filter = new CooperatingFilterWrapper(new UserAgentBypassFilterWrapper(new AuthenticationFilter()), AUTH_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 2
        frb.urlPatterns = casClientProperties.authenticateOnlyIfLoggedInPattern + casClientProperties.authenticateOnlyIfLoggedInFilterPattern
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'true']
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casValidationFilter() {
        def frb = new FilterRegistrationBean()
        frb.name = 'CAS Validation Filter'
        frb.filter = new CooperatingFilterWrapper(new Cas30ProxyReceivingTicketValidationFilter(), VALIDATION_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 3
        frb.urlPatterns = casClientProperties.uriFilterPattern
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'false']
        return frb
    }

    @ConditionalOnProperty(prefix= 'security.cas', name='enabled', matchIfMissing = true)
    @Bean
    FilterRegistrationBean casValidationGatewayFilter() {
        def frb = new FilterRegistrationBean()
        frb.name = 'CAS Gateway Validation Filter'
        frb.filter = new CooperatingFilterWrapper(new UserAgentBypassFilterWrapper(new Cas30ProxyReceivingTicketValidationFilter()), VALIDATION_FILTER_KEY)
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
        frb.order = filterOrder() + 4
        frb.urlPatterns = casClientProperties.authenticateOnlyIfLoggedInPattern + casClientProperties.authenticateOnlyIfLoggedInFilterPattern
        frb.asyncSupported = true
        frb.initParameters = [(ConfigurationKeys.GATEWAY.name) : 'true']
        return frb
    }

    @Bean
    FilterRegistrationBean casHttpServletRequestWrapperFilter() {
        FilterRegistrationBean frb = new FilterRegistrationBean()
        frb.name = 'CAS HttpServletRequest Wrapper Filter'
        frb.filter = new HttpServletRequestWrapperFilter()
        frb.dispatcherTypes = EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR)
        frb.order = filterOrder() + 5
        frb.urlPatterns = ['/*']
        frb.asyncSupported = true
        frb.initParameters = [:]
        return frb
    }

}
