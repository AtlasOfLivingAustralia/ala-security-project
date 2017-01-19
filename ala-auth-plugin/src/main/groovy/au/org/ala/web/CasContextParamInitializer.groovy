package au.org.ala.web

import au.org.ala.cas.client.UriFilter
import grails.core.GrailsApplication
import groovy.util.logging.Slf4j
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.web.servlet.ServletContextInitializer
import org.springframework.stereotype.Component

import javax.servlet.ServletContext
import javax.servlet.ServletException

import static au.org.ala.cas.client.UriFilter.AUTHENTICATE_ONLY_IF_LOGGED_IN_FILTER_PATTERN
import static au.org.ala.cas.client.UriFilter.URI_EXCLUSION_FILTER_PATTERN
import static au.org.ala.cas.client.UriFilter.URI_FILTER_PATTERN

@Component
@Slf4j
class CasContextParamInitializer implements ServletContextInitializer {

    @Autowired
    GrailsApplication grailsApplication

    @Override
    void onStartup(ServletContext servletContext) throws ServletException {
        log.debug("CAS Servlet Context Initializer")
        def appServerName = grailsApplication.config.security.cas.appServerName
        def service = grailsApplication.config.security.cas.service
        if (!appServerName && !service) {
            def message = "One of 'security.cas.appServerName' or 'security.cas.service' config settings is required by the CAS filters."
            log.error(message)
            throw new IllegalStateException(message)
        }
        if (appServerName) {
            servletContext.setInitParameter('serverName', appServerName)
        }
        if (service) {
            servletContext.setInitParameter('service', service)
        }
        servletContext.setInitParameter('casServerName', grailsApplication.config.security.cas.casServerName)
        servletContext.setInitParameter(URI_FILTER_PATTERN, grailsApplication.config.security.cas.uriFilterPattern)
        servletContext.setInitParameter(URI_EXCLUSION_FILTER_PATTERN, grailsApplication.config.security.cas.uriExclusionFilterPattern)
        servletContext.setInitParameter(AUTHENTICATE_ONLY_IF_LOGGED_IN_FILTER_PATTERN, grailsApplication.config.security.cas.authenticateOnlyIfLoggedInPattern)

        def encodeServiceUrl = grailsApplication.config.security.cas.encodeServiceUrl
        if (isBoolesque(encodeServiceUrl)) {
            servletContext.setInitParameter('encodeServiceUrl', encodeServiceUrl.toString())
        }

        def contextPath = grailsApplication.config.security.cas.contextPath
        if (contextPath) {
            log.warn("Setting security.cas.contextPath is unnecessary, ala-cas-client can now retrieve it from the ServletContext")
            servletContext.setInitParameter('contextPath', contextPath)
        }
    }

    private static boolean isBoolesque(o) {
        if (o instanceof Boolean) {
            return true
        }
        if (o instanceof String) {
            if (o.equalsIgnoreCase('true') || o.equalsIgnoreCase('false')) {
                return true
            } else {
                log.warn("$o is not a boolean value")
            }
        }
        return false
    }
}
