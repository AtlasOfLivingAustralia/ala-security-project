import au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter
import au.org.ala.cas.client.UriFilter
import au.org.ala.web.SecurityPrimitives
import au.org.ala.web.config.AuthPluginConfig
import au.org.ala.web.filter.ParametersFilterProxy
import grails.plugin.webxml.FilterManager
import grails.util.Environment
import grails.util.Holders
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener
import org.jasig.cas.client.util.HttpServletRequestWrapperFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter
import org.springframework.web.filter.DelegatingFilterProxy

class AlaAuthGrailsPlugin {
    // the plugin version
    def version = "2.2-SNAPSHOT"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.3.0 > *"
    // the other plugins this plugin depends on
    def dependsOn = [:]
    // resources that are excluded from plugin packaging
    def pluginExcludes = ["grails-app/views/error.gsp"]

    def title = "Ala Auth Plugin" // Headline display name of the plugin
    def author = "Nick dos Remedios"
    def authorEmail = "nick.dosremedios@csiro.au"
    def description = "This plugin provides auth services for ALA."

    // URL to the plugin's documentation
    def documentation = "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin"

    // License: one of 'APACHE', 'GPL2', 'GPL3'
    def license = "MPL2"

    // Details of company behind the plugin (if there is one)
    def organization = [ name: "Atlas of Living Australia", url: "http://www.ala.org.au/" ]

    // Any additional developers beyond the author specified above.
    def developers = [ [ name: "Nick dos Remedios", email: "nick.dosremedios@csiro.au" ], [ name: "Dave Martin", email: "david.martin@csiro.au" ], [ name: 'Simon Bear', email: 'simon.bear@csiro.au' ]]

    // Location of the plugin's issue tracker.
    def issueManagement = [ system: "github", url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin/issues" ]

    // Online location of the plugin's browseable source code.
    def scm = [ url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin" ]

    // make sure the filter chain filter is the character encoding filter but before Grails
    def getWebXmlFilterOrder() {
        [
            casSingleSignOutFilter             : FilterManager.DEFAULT_POSITION + 100,
            casAuthenticationFilter            : FilterManager.DEFAULT_POSITION + 101,
            casValidationFilter                : FilterManager.DEFAULT_POSITION + 102,
            casHttpServletRequestWrapperFilter : FilterManager.DEFAULT_POSITION + 103
        ]
    }

    // Note: ONLY evaluated at compile time (not run time)
    def doWithWebDescriptor = { xml ->
        def mappingElement = xml.'filter'
        def mappingLocation = mappingElement[mappingElement.size()-1]
        mappingLocation + {
            'filter' {
                'filter-name'('casSingleSignOutFilter')
                'filter-class'('org.jasig.cas.client.session.SingleSignOutFilter')
                'async-supported'('true')
            }
            'filter' {
                'filter-name'('casAuthenticationFilter')
                'filter-class'(DelegatingFilterProxy.name)
                'async-supported'('true')
                'init-param' {
                    'param-name'('targetFilterLifecycle')
                    'param-value'('true')
                }
            }
            'filter' {
                'filter-name'('casValidationFilter')
                'filter-class'(DelegatingFilterProxy.name)
                'async-supported'('true')
                'init-param' {
                    'param-name'('targetFilterLifecycle')
                    'param-value'('true')
                }
            }
            'filter' {
                'filter-name'('casHttpServletRequestWrapperFilter')
                'filter-class'(HttpServletRequestWrapperFilter.name)
                'async-supported'('true')
                'init-param' {
                    'param-name'('targetFilterLifecycle')
                    'param-value'('true')
                }
            }
        }
        findMappingLocation.delegate = delegate
        mappingLocation = findMappingLocation(xml)
        mappingLocation + {
            'filter-mapping' {
                'filter-name' ('casSingleSignOutFilter')
                'url-pattern' ('/*')
                dispatcher('REQUEST')
            }
            'filter-mapping' {
                'filter-name' ('casAuthenticationFilter')
                'url-pattern' ('/*')
                dispatcher('REQUEST')
            }
            'filter-mapping' {
                'filter-name' ('casValidationFilter')
                'url-pattern' ('/*')
                dispatcher('REQUEST')
            }
            'filter-mapping' {
                'filter-name' ('casHttpServletRequestWrapperFilter')
                'url-pattern' ('/*')
                dispatcher('ERROR')
                dispatcher('REQUEST')
            }
        }

        mappingLocation = xml.'filter-mapping'
        mappingLocation[mappingLocation.size() - 1] + {
            listener {
                'listener-class'(SingleSignOutHttpSessionListener.name)
            }
        }

        if (Holders.config.security.cas.debugWebXml) {
            println "web.xml = ${xml}"
        }
    }

    def doWithSpring = {
        mergeConfig(application)

        def config = application.config
        def disableCAS = config.security.cas.bypass.toString()

        casAuthenticationFilter(ParametersFilterProxy) {
            filter = new UriFilter()
            initParameters = [
                    'filterClass': AuthenticationFilter.name,
                    'disableCAS': disableCAS
            ]
        }

        casValidationFilter(ParametersFilterProxy) {
            filter = new UriFilter()
            initParameters = [
                    'filterClass': Cas30ProxyReceivingTicketValidationFilter.name,
                    'disableCAS': disableCAS
            ]
        }

        alaAuthPluginConfiguration(AuthPluginConfig)

        securityPrimitives(SecurityPrimitives) { beanDefinition ->
            beanDefinition.constructorArgs = [ref('authService'), ref('grailsApplication')]
        }
    }

    def doWithDynamicMethods = { ctx ->
    }

    def doWithApplicationContext = { applicationContext ->

    }

    def onChange = { event ->
    }

    def onConfigChange = { event ->
        this.mergeConfig(application)
    }

    def onShutdown = { event ->
    }

    private findMappingLocation = { xml ->

        // find the location to insert the filter-mapping; needs to be after the 'charEncodingFilter'
        // which may not exist. should also be before the sitemesh filter.
        // thanks to the JSecurity plugin for the logic.

        def mappingLocation = xml.'filter-mapping'.find { it.'filter-name'.text() == 'charEncodingFilter' }
        if (mappingLocation) {
            return mappingLocation
        }

        // no 'charEncodingFilter'; try to put it before sitemesh
        int i = 0
        int siteMeshIndex = -1
        xml.'filter-mapping'.each {
            if (it.'filter-name'.text().equalsIgnoreCase('sitemesh')) {
                siteMeshIndex = i
            }
            i++
        }
        if (siteMeshIndex > 0) {
            return xml.'filter-mapping'[siteMeshIndex - 1]
        }

        if (siteMeshIndex == 0 || xml.'filter-mapping'.size() == 0) {
            def filters = xml.'filter'
            return filters[filters.size() - 1]
        }

        // neither filter found
        def filters = xml.'filter'
        return filters[filters.size() - 1]
    }

    private void mergeConfig(GrailsApplication app) {
        ConfigObject currentCasConfig = app.config.security.cas
        ConfigObject currentUserDetailsConfig = app.config.userDetails
        ConfigObject currentCacheConfig = app.config.grails.cache

        ConfigSlurper slurper = new ConfigSlurper(Environment.current.name)
        ConfigObject secondaryConfig = slurper.parse(app.classLoader.loadClass("AlaAuthPluginConfig"))

        ConfigObject casConfig = new ConfigObject()
        casConfig.putAll(secondaryConfig.security.cas.merge(currentCasConfig))

        app.config.security.cas = casConfig

        ConfigObject userDetailsConfig = new ConfigObject()
        userDetailsConfig.putAll(secondaryConfig.userDetails.merge(currentUserDetailsConfig))

        app.config.userDetails = userDetailsConfig

        ConfigObject cacheConfig = new ConfigObject()
        cacheConfig.putAll(secondaryConfig.grails.cache.merge(currentCacheConfig))

        app.config.grails.cache = cacheConfig
    }
}
