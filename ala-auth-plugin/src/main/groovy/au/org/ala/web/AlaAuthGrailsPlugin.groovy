package au.org.ala.web

import au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter
import au.org.ala.cas.client.UriFilter
import au.org.ala.web.config.PluginConfig
import grails.plugins.*
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter
import org.springframework.boot.web.servlet.FilterRegistrationBean

class AlaAuthPluginGrailsPlugin extends Plugin {

    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.2.4 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = [
        "grails-app/views/error.gsp"
    ]

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
    def developers = [ [ name: "Simon Bear", email: "simon.bear@csiro.au" ], [ name: "Chris Godwin", email: "chris.godwin.ala@gmail.com" ], [ name: "Peter Ansell", email: "p_ansell@yahoo.com" ], [ name: "Dave Martin", email: "david.martin@csiro.au" ]]

    // Location of the plugin's issue tracker.
    def issueManagement = [ system: "github", url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin/issues" ]

    // Online location of the plugin's browseable source code.
    def scm = [ url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin" ]

    Closure doWithSpring() { {->
            casContextParamInitializer(CasContextParamInitializer)

            casSSOFilter(FilterRegistrationBean) {
                name = 'Cas Single Sign Out Filter'
                filter = bean(SingleSignOutFilter)
                order = 1
                urlPatterns = ['/*']
            }
            casAuthFilter(FilterRegistrationBean) {
                name = 'CAS Authentication Filter'
                filter = bean(UriFilter)
                order = 2
                urlPatterns = ['/*']
                initParameters = [
                        'filterClass': AuthenticationFilter.name,
                        'casServerLoginUrl': grailsApplication.config.security.cas.loginUrl,
                        'gateway': 'false',
                        'disableCAS': grailsApplication.config.security.cas.bypass.toString()
                ]
            }
            casValidationFilter(FilterRegistrationBean) {
                name = 'CAS Validation Filter'
                filter = bean(UriFilter)
                order = 3
                urlPatterns = ['/*']
                initParameters = [
                        'filterClass': Cas20ProxyReceivingTicketValidationFilter.name,
                        'disableCAS': grailsApplication.config.security.cas.bypass.toString(),
                        'casServerUrlPrefix': grailsApplication.config.security.cas.casServerUrlPrefix
                ]
            }
            casHttpServletRequestWrapperFilter(FilterRegistrationBean) {
                name = 'CAS HttpServletRequest Wrapper Filter'
                filter = bean(UriFilter)
                order = 4
                urlPatterns = ['/*']
                initParameters = [
                        'filterClass': AlaHttpServletRequestWrapperFilter.name,
                        'disableCAS': grailsApplication.config.security.cas.bypass.toString(),
                ]
            }

            alaAuthPluginConfiguration(PluginConfig)

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
