package au.org.ala.web

import au.org.ala.web.config.AuthGenericPluginConfig
import au.org.ala.web.config.AuthPac4jPluginConfig
import au.org.ala.web.config.AuthPluginConfig
import au.org.ala.web.config.MongoSpringSessionPluginConfig
import au.org.ala.web.config.SpringSessionPluginConfig
import grails.plugins.*
import groovy.util.logging.Slf4j

@Slf4j
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

            authGenericPluginConfiguration(AuthGenericPluginConfig)
            alaAuthPluginConfiguration(AuthPluginConfig)
            authOidcPluginConfiguration(AuthPac4jPluginConfig)
//            springSessionPluginConfiguration(SpringSessionPluginConfig) // included via spring.factories
//            mongoSpringSessionPluginConfiguration(MongoSpringSessionPluginConfig)

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
