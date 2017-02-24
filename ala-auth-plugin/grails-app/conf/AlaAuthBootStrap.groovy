import org.apache.log4j.Logger

import javax.servlet.ServletContext

import static au.org.ala.cas.client.UriFilter.AUTHENTICATE_ONLY_IF_LOGGED_IN_FILTER_PATTERN
import static au.org.ala.cas.client.UriFilter.URI_EXCLUSION_FILTER_PATTERN
import static au.org.ala.cas.client.UriFilter.URI_FILTER_PATTERN
import static org.jasig.cas.client.configuration.ConfigurationKeys.*

class AlaAuthBootStrap {

    private static final Logger logger = Logger.getLogger(AlaAuthBootStrap)

    def grailsApplication

    def init = { ServletContext servletContext ->
        def appServerName = grailsApplication.config.security.cas.appServerName
        def service = grailsApplication.config.security.cas.service
        if (!appServerName && !service) {
            def message = "One of 'security.cas.appServerName' or 'security.cas.service' config settings is required by the CAS filters."
            log.error(message)
            throw new IllegalStateException(message)
        }
        if (appServerName) {
            servletContext.setInitParameter(SERVER_NAME.name, appServerName)
        }
        if (service) {
            servletContext.setInitParameter(SERVICE.name, service)
        }
        servletContext.setInitParameter(CAS_SERVER_URL_PREFIX.name, grailsApplication.config.security.cas.casServerUrlPrefix)
        servletContext.setInitParameter(CAS_SERVER_LOGIN_URL.name, grailsApplication.config.security.cas.loginUrl)

        servletContext.setInitParameter('casServerName', grailsApplication.config.security.cas.casServerName)

        servletContext.setInitParameter(URI_FILTER_PATTERN, grailsApplication.config.security.cas.uriFilterPattern)
        servletContext.setInitParameter(URI_EXCLUSION_FILTER_PATTERN, grailsApplication.config.security.cas.uriExclusionFilterPattern)
        servletContext.setInitParameter(AUTHENTICATE_ONLY_IF_LOGGED_IN_FILTER_PATTERN, grailsApplication.config.security.cas.authenticateOnlyIfLoggedInPattern)

        def encodeServiceUrl = grailsApplication.config.security.cas.encodeServiceUrl
        if (isBoolesque(encodeServiceUrl)) {
            servletContext.setInitParameter(ENCODE_SERVICE_URL.name, encodeServiceUrl.toString())
        }

        def contextPath = grailsApplication.config.security.cas.contextPath
        if (contextPath) {
            log.warn("Setting security.cas.contextPath ($contextPath) is unnecessary, ala-cas-client can now retrieve it from the ServletContext")
            servletContext.setInitParameter('contextPath', contextPath)
        }

        def gateway = grailsApplication.config.security.cas.gateway
        if (isBoolesque(gateway)) {
            servletContext.setInitParameter(GATEWAY.name, gateway.toString())
        }

        def gatewayStorageClass = grailsApplication.config.security.cas.gatewayStorageClass
        if (gatewayStorageClass) {
            servletContext.setInitParameter(GATEWAY_STORAGE_CLASS.name, gatewayStorageClass)
        }

        def renew = grailsApplication.config.security.cas.renew
        if (isBoolesque(renew)) {
            servletContext.setInitParameter(RENEW.name, renew.toString())
        }
    }

    def destroy = {
    }

    private static boolean isBoolesque(o) {
        if (o instanceof Boolean) {
            return true
        }
        if (o instanceof String) {
            if (o.equalsIgnoreCase('true') || o.equalsIgnoreCase('false')) {
                return true
            } else {
                logger.warn("$o is not a boolean value")
            }
        }
        return false
    }
}
