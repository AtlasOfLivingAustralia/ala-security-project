package au.org.ala.web

import au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter
import au.org.ala.cas.client.UriFilter
import au.org.ala.web.config.AuthPluginConfig
import grails.plugins.*
import grails.util.Metadata
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.core.Ordered

import javax.servlet.DispatcherType

class AlaAuthGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.2.4 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = []

    def title = "Ala Auth Plugin" // Headline display name of the plugin
    def author = "Nick dos Remedios"
    def authorEmail = "nick.dosremedios@csiro.au"
    def description = '''\
This plugin provides auth services for ALA.
'''

    // URL to the plugin's documentation
    def documentation = "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin"

    // Extra (optional) plugin metadata

    // License: one of 'APACHE', 'GPL2', 'GPL3'
    def license = "MPL2"

    // Details of company behind the plugin (if there is one)
    def organization = [ name: "Atlas of Living Australia", url: "http://www.ala.org.au/" ]

    // Any additional developers beyond the author specified above.
    def developers = [ [ name: "Peter Ansell", email: "p_ansell@yahoo.com" ], [ name: "Simon Bear", email: "simon.bear@csiro.au" ], [ name: "Nick dos Remedios", email: "nick.dosremedios@csiro.au" ], [ name: "Chris Godwin", email: "chris.godwin.ala@gmail.com" ], [ name: "Dave Martin", email: "david.martin@csiro.au" ]]

    // Location of the plugin's issue tracker.
    def issueManagement = [ system: "github", url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin/issues" ]

    // Online location of the plugin's browseable source code.
    def scm = [ url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin" ]

    Closure doWithSpring() { {->
            casContextParamInitializer(CasContextParamInitializer)

            // The filter chain has to be before grailsWebRequestFilter but after the encoding filter.
            // Its order changed in 3.1 (from Ordered.HIGHEST_PRECEDENCE + 30 (-2147483618) to
            // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 30 (30))
            def filterOrder
            String grailsVersion = Metadata.current.getGrailsVersion()
            if (grailsVersion.startsWith('3.0')) {
                filterOrder = Ordered.HIGHEST_PRECEDENCE + 21
            }
            else {
                filterOrder = 21 // FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER + 21
            }

            casSSOFilter(FilterRegistrationBean) {
                name = 'Cas Single Sign Out Filter'
                filter = bean(SingleSignOutFilter)
                dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
                order = filterOrder
                urlPatterns = ['/*']
                asyncSupported = true
            }
            casAuthFilter(FilterRegistrationBean) {
                name = 'CAS Authentication Filter'
                filter = bean(UriFilter)
                dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
                order = filterOrder + 1
                urlPatterns = ['/*']
                asyncSupported = true
                initParameters = [
                        'filterClass': AuthenticationFilter.name,
                        'disableCAS': grailsApplication.config.security.cas.bypass.toString()
                ]
            }
            casValidationFilter(FilterRegistrationBean) {
                name = 'CAS Validation Filter'
                filter = bean(UriFilter)
                dispatcherTypes = EnumSet.of(DispatcherType.REQUEST)
                order = filterOrder + 2
                urlPatterns = ['/*']
                asyncSupported = true
                initParameters = [
                        'filterClass': Cas30ProxyReceivingTicketValidationFilter.name,
                        'disableCAS': grailsApplication.config.security.cas.bypass.toString()
                ]
            }
            casHttpServletRequestWrapperFilter(FilterRegistrationBean) {
                name = 'CAS HttpServletRequest Wrapper Filter'
                filter = bean(HttpServletRequestWrapperFilter)
                dispatcherTypes = EnumSet.of(DispatcherType.REQUEST, DispatcherType.ERROR)
                order = filterOrder + 3
                urlPatterns = ['/*']
                asyncSupported = true
                initParameters = [
                ]
            }

            alaAuthPluginConfiguration(AuthPluginConfig)

            securityPrimitives(SecurityPrimitives) { beanDefinition ->
                beanDefinition.constructorArgs = [ref('authService'), ref('grailsApplication')]
            }
        }
    }

    void doWithDynamicMethods() {
    }

    void doWithApplicationContext() {
    }

    void onChange(Map<String, Object> event) {
    }

    void onConfigChange(Map<String, Object> event) {
    }

    void onShutdown(Map<String, Object> event) {
    }
}
