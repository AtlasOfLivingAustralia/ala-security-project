// configuration for plugin testing - will not be included in the plugin zip
grails.hostname = "devt.ala.org.au"
grails.serverURL = "http://${grails.hostname}:8080/" + appName
// CAS security conf
security.cas.casServerName = 'https://nci-auth.ala.org.au'
security.cas.uriFilterPattern = "/admin/.*, /testAuth,/authTest/.*" // pattern for pages that require authentication
security.cas.uriExclusionFilterPattern = '/images.*,/css.*,/js.*,/less.*'
security.cas.authenticateOnlyIfLoggedInPattern = "" // pattern for pages that can optionally display info about the logged-in user
security.cas.casServerUrlPrefix = ${security.cas.casServerName} + '/cas'
security.cas.loginUrl = ${security.cas.casServerUrlPrefix} + '/login'
security.cas.logoutUrl = ${security.cas.casServerUrlPrefix} + '/logout'
security.cas.bypass = false
security.cas.appServerName = "http://${grails.hostname}:8080"
security.cas.contextPath = "/" + appName

log4j = {
    // Example of changing the log pattern for the default console
    // appender:
    //
    appenders {
        //console name:'stdout', layout:pattern(conversionPattern: '%c{2} %m%n')
        environments {
            development {
                console name: "stdout", layout: pattern(conversionPattern: "%d [%c{1}]  %m%n"),
                        threshold: org.apache.log4j.Level.DEBUG
            }
        }
    }

    error  'org.codehaus.groovy.grails.web.servlet',  //  controllers
           'org.codehaus.groovy.grails.web.pages', //  GSP
           'org.codehaus.groovy.grails.web.sitemesh', //  layouts
           'org.codehaus.groovy.grails.web.mapping.filter', // URL mapping
           'org.codehaus.groovy.grails.web.mapping', // URL mapping
           'org.codehaus.groovy.grails.commons', // core / classloading
           'org.codehaus.groovy.grails.plugins', // plugins
           'org.codehaus.groovy.grails.orm.hibernate', // hibernate integration
           'org.springframework',
           'org.hibernate',
           'net.sf.ehcache.hibernate'

    warn   'org.mortbay.log'

    environments {

        test {
            info   'grails.app'
        }
        development {
            // Override previous setting for 'grails.app'
//            info   'grails.app'
            debug  'grails.app.services.au.org.ala.web','grails.app.controllers.au.org.ala.web'
        }
    }
} //grails.views.default.codec="none" // none, html, base64
grails.views.gsp.encoding="UTF-8"

// Uncomment and edit the following lines to start using Grails encoding & escaping improvements

/* remove this line 
// GSP settings
grails {
    views {
        gsp {
            encoding = 'UTF-8'
            htmlcodec = 'xml' // use xml escaping instead of HTML4 escaping
            codecs {
                expression = 'html' // escapes values inside null
                scriptlet = 'none' // escapes output from scriptlets in GSPs
                taglib = 'none' // escapes output from taglibs
                staticparts = 'none' // escapes output from static template parts
            }
        }
        // escapes all not-encoded output at final stage of outputting
        filteringCodecForContentType {
            //'text/html' = 'html'
        }
    }
}
remove this line */
