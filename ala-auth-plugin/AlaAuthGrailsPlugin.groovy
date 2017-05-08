import au.org.ala.web.SecurityPrimitives
import au.org.ala.web.config.AuthPluginConfig

import grails.util.Environment
import org.codehaus.groovy.grails.commons.GrailsApplication

class AlaAuthGrailsPlugin {
    // the plugin version
    def version = "2.1.0-SNAPSHOT"
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
    }

    def doWithSpring = {
        mergeConfig(application)

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
