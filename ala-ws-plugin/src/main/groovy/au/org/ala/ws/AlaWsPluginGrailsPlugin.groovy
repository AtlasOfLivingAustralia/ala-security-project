package au.org.ala.ws

import au.org.ala.ws.config.AlaWsPluginConfig

class AlaWsPluginGrailsPlugin {
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "3.1.0 > *"
    // resources that are excluded from plugin packaging
    def pluginExcludes = []

    def title = "ALA WS Plugin" // Headline display name of the plugin
    def author = "Atlas of Living Australia"
    def authorEmail = ""
    def description = "Grails plugin containing common REST and general webservice functionality."

    def profiles = ['web']

    // URL to the plugin's documentation
    def documentation = "https://github.com/AtlasOfLivingAustralia/ala-ws-plugin"

    // License: one of 'APACHE', 'GPL2', 'GPL3'
    def license = "MPL-2.0"

    // Details of company behind the plugin (if there is one)
    def organization = [ name: "Atlas of Living Australia", url: "http://ala.org.au" ]

    def doWithWebDescriptor = { xml ->
    }

    def doWithSpring = {
        alaWsPluginConfg(AlaWsPluginConfig)
    }

    def doWithDynamicMethods = { ctx ->
    }

    def doWithApplicationContext = { ctx ->
    }

    def onChange = { event ->
    }

    def onConfigChange = { event ->
    }

    def onShutdown = { event ->
    }
}
