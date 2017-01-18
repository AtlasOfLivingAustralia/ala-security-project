import au.org.ala.web.SecurityPrimitives
import grails.util.Holders

class AlaAuthGrailsPlugin {
    // the plugin version
    def version = "1.3.4"
    // the version or versions of Grails the plugin is designed for
    def grailsVersion = "2.2 > *"
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
    def developers = [ [ name: "Nick dos Remedios", email: "nick.dosremedios@csiro.au" ], [ name: "Dave Martin", email: "david.martin@csiro.au" ]]

    // Location of the plugin's issue tracker.
    def issueManagement = [ system: "github", url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin/issues" ]

    // Online location of the plugin's browseable source code.
    def scm = [ url: "https://github.com/AtlasOfLivingAustralia/ala-auth-plugin" ]

    // Note: ONLY evaluated at compile time (not run time)
    def doWithWebDescriptor = { xml ->
        def mappingElement = xml.'context-param'
        def lastMapping = mappingElement[mappingElement.size()-1]
        String defaultConfig = Holders.config.default_config

        if (Holders.config.runWithNoExternalConfig == true) {
            // No external config file set, use security.cas.* settings embedded un web.xml instead
            if (!Holders.config.security.cas || Holders.config.security.cas.size() == 0) {
                println "No security.cas.* settings found (or external conf found) - setting bypass = true"
                Holders.config.security.cas.bypass = true
            }

            lastMapping + {
                'context-param' {
                    'param-name' ('serverName')
                    'param-value' (Holders.config.security.cas.appServerName)
                }
                'context-param' {
                    'param-name' ('casServerName')
                    'param-value' (Holders.config.security.cas.casServerName)
                }
                'context-param' {
                    'param-name' ('uriFilterPattern')
                    'param-value' (Holders.config.security.cas.uriFilterPattern)
                }
                'context-param' {
                    'param-name' ('uriExclusionFilterPattern')
                    'param-value' (Holders.config.security.cas.uriExclusionFilterPattern)
                }
                'context-param' {
                    'param-name' ('authenticateOnlyIfLoggedInFilterPattern')
                    'param-value' (Holders.config.security.cas.authenticateOnlyIfLoggedInPattern)
                }
            }

            if (Holders.config.security.cas.contextPath) {
                lastMapping + {
                    'context-param' {
                        'param-name' ('contextPath')
                        'param-value' (Holders.config.security.cas.contextPath)
                    }
                }
            }
        } else {
            // Use `configPropFile` external config which is read by ala-cas-client-2.0-SNAPSHOT.jar
            lastMapping + {
                'env-entry' {
                    'env-entry-name' ('configPropFile')
                    'env-entry-value' (defaultConfig)
                    'env-entry-type' ('java.lang.String')
                }
            }
        }

        mappingElement = xml.'filter'
        lastMapping = mappingElement[mappingElement.size()-1]
        lastMapping + {
            'filter' {
                'filter-name' ('CAS Single Sign Out Filter')
                'filter-class' ('org.jasig.cas.client.session.SingleSignOutFilter')
            }
            'filter' {
                'filter-name' ('CAS Authentication Filter')
                'filter-class' ('au.org.ala.cas.client.UriFilter')
                'init-param' {
                    'param-name' ('filterClass')
                    'param-value' ('org.jasig.cas.client.authentication.AuthenticationFilter')
                }
                'init-param' {
                    'param-name' ('casServerLoginUrl')
                    'param-value' (Holders.config.security.cas.loginUrl)
                }
                'init-param' {
                    'param-name' ('gateway')
                    'param-value' ('false')
                }
                'init-param' {
                    'param-name' ('disableCAS')
                    'param-value' (Holders.config.security.cas.bypass == true ? 'true' : 'false')
                }
            }
            'filter' {
                'filter-name' ('CAS Validation Filter')
                'filter-class' ('au.org.ala.cas.client.UriFilter')
                'init-param' {
                    'param-name' ('filterClass')
                    'param-value' ('org.jasig.cas.client.validation.Cas20ProxyReceivingTicketValidationFilter')
                }
                'init-param' {
                    'param-name' ('disableCAS')
                    'param-value' (Holders.config.security.cas.bypass == true ? 'true' : 'false')
                }
                'init-param' {
                    'param-name' ('casServerUrlPrefix')
                    'param-value' (Holders.config.security.cas.casServerUrlPrefix)
                }
            }
            'filter' {
                'filter-name' ('CAS HttpServletRequest Wrapper Filter')
                'filter-class' ('au.org.ala.cas.client.UriFilter')
                'init-param' {
                    'param-name' ('filterClass')
                    'param-value' ('au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter')
                }
                'init-param' {
                    'param-name' ('disableCAS')
                    'param-value' (Holders.config.security.cas.bypass == true ? 'true' : 'false')
                }
            }
            'filter-mapping' {
                'filter-name' ('CAS Single Sign Out Filter')
                'url-pattern' ('/*')
            }
            'filter-mapping' {
                'filter-name' ('CAS Authentication Filter')
                'url-pattern' ('/*')
            }
            'filter-mapping' {
                'filter-name' ('CAS Validation Filter')
                'url-pattern' ('/*')
            }
            'filter-mapping' {
                'filter-name' ('CAS HttpServletRequest Wrapper Filter')
                'url-pattern' ('/*')
            }
        }

        if (Holders.config.security.cas.debugWebXml) {
            println "web.xml = ${mappingElement}"
        }
    }

    def doWithSpring = {
        //System.println("Merging conf...")
        //mergeConfig(application)
        def config = application.config

        if (!config.userDetails.url) {
            config.userDetails.url = "https://auth.ala.org.au/userdetails/userDetails/"
        }

        if (!config.userDetails.path) {
            config.userDetails.path = "getUserListFull"
        }

        if (!config.userDetailsById.path) {
            config.userDetailsById.path = "getUserDetails"
        }

        if (!config.userDetailsById.bulkPath) {
            config.userDetailsById.bulkPath = 'getUserDetailsFromIdList'
        }

        if (!config.grails.cache.config) {
            config.grails.cache.config = {
                defaults {
                    eternal false
                    overflowToDisk false
                    maxElementsInMemory 20000
                    timeToLiveSeconds 3600
                }
                cache {
                    name 'userListCache'
                }
                cache {
                    name 'userMapCache'
                }

            }
        }

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
    }

    def onShutdown = { event ->
    }
}
