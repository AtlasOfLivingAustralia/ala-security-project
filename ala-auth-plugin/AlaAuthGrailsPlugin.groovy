import au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter
import au.org.ala.cas.client.UriFilter
import au.org.ala.web.SecurityPrimitives
import au.org.ala.web.config.AuthPluginConfig
import au.org.ala.web.filter.ParametersFilterProxy
import grails.util.Environment
import grails.util.Holders
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter

class AlaAuthGrailsPlugin {
    // the plugin version
    def version = "2.0.0-SNAPSHOT"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.5.5 > *"
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

    // Note: ONLY evaluated at compile time (not run time)
    def doWithWebDescriptor = { xml ->
        def mappingElement = xml.'context-param'
        def lastMapping = mappingElement[mappingElement.size()-1]
        String defaultConfig = Holders.config.default_config

        lastMapping + {
            'context-param' {
                'param-name'('configurationStrategy')
                'param-value'('WEB_XML')
            }
        }

        mappingElement = xml.'filter'
        lastMapping = mappingElement[mappingElement.size()-1]
        lastMapping + {
            'filter' {
                'filter-name' ('CAS Single Sign Out Filter')
                'filter-class' ('org.jasig.cas.client.session.SingleSignOutFilter')
                'async-supported' ('true')
            }
            'filter' {
                'filter-name' ('casAuthenticationFilter')
                'filter-class' ('org.springframework.web.filter.DelegatingFilterProxy')
                'async-supported' ('true')
                'init-param' {
                    'param-name' ('targetFilterLifecycle')
                    'param-value' ('true')
                }
            }
            'filter' {
                'filter-name' ('casValidationFilter')
                'filter-class' ('org.springframework.web.filter.DelegatingFilterProxy')
                'async-supported' ('true')
                'init-param' {
                    'param-name' ('targetFilterLifecycle')
                    'param-value' ('true')
                }
            }
            'filter' {
                'filter-name' ('casHttpServletRequestWrapperFilter')
                'filter-class' ('org.springframework.web.filter.DelegatingFilterProxy')
                'async-supported' ('true')
                'init-param' {
                    'param-name' ('targetFilterLifecycle')
                    'param-value' ('true')
                }
            }
            'filter-mapping' {
                'filter-name' ('CAS Single Sign Out Filter')
                'url-pattern' ('/*')
            }
            'filter-mapping' {
                'filter-name' ('casAuthenticationFilter')
                'url-pattern' ('/*')
            }
            'filter-mapping' {
                'filter-name' ('casValidationFilter')
                'url-pattern' ('/*')
            }
            'filter-mapping' {
                'filter-name' ('casHttpServletRequestWrapperFilter')
                'url-pattern' ('/*')
            }
        }

        if (Holders.config.security.cas.debugWebXml) {
            println "web.xml = ${xml}"
        }
    }

    def doWithSpring = {
        mergeConfig(application)
        //System.println("Merging conf...")
        //mergeConfig(application)
        def config = application.config

        casAuthenticationFilter(ParametersFilterProxy) {
            filter = new UriFilter()
            initParameters = [
                    'filterClass': AuthenticationFilter.name,
                    'disableCAS': config.security.cas.bypass.toString()
            ]
        }

        casValidationFilter(ParametersFilterProxy) {
            filter = new UriFilter()
            initParameters = [
                    'filterClass': Cas30ProxyReceivingTicketValidationFilter.name,
                    'disableCAS': config.security.cas.bypass.toString()
            ]
        }
        casHttpServletRequestWrapperFilter(ParametersFilterProxy) {
            filter = new UriFilter()
            initParameters = [
                    'filterClass': AlaHttpServletRequestWrapperFilter.name,
                    'disableCAS': config.security.cas.bypass.toString(),
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

    private void mergeConfig(GrailsApplication app) {
        ConfigObject currentCasConfig = app.config.security.cas
        ConfigObject currentUserDetailsConfig = app.config.userdetails
        ConfigObject currentCacheConfig = app.config.grails.cache

        ConfigSlurper slurper = new ConfigSlurper(Environment.current.name)
        ConfigObject secondaryConfig = slurper.parse(app.classLoader.loadClass("AlaAuthPluginConfig"))

        ConfigObject casConfig = new ConfigObject()
        casConfig.putAll(secondaryConfig.security.cas.merge(currentCasConfig))

        app.config.security.cas = casConfig

        ConfigObject userDetailsConfig = new ConfigObject()
        userDetailsConfig.putAll(secondaryConfig.userdetails.merge(currentUserDetailsConfig))

        app.config.userdetails = userDetailsConfig

        ConfigObject cacheConfig = new ConfigObject()
        cacheConfig.putAll(secondaryConfig.grails.cache.merge(currentCacheConfig))

        app.config.grails.cache = cacheConfig
    }
}
