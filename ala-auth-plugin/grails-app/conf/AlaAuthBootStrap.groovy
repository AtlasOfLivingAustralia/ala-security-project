import au.org.ala.cas.client.AlaHttpServletRequestWrapperFilter
import au.org.ala.cas.client.UriFilter
import org.apache.log4j.Logger
import org.codehaus.groovy.runtime.typehandling.GroovyCastException
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.session.SingleSignOutFilter
import org.jasig.cas.client.validation.Cas30ProxyReceivingTicketValidationFilter

import javax.servlet.DispatcherType
import javax.servlet.ServletContext

import static au.org.ala.cas.client.UriFilter.AUTHENTICATE_ONLY_IF_LOGGED_IN_FILTER_PATTERN
import static au.org.ala.cas.client.UriFilter.URI_EXCLUSION_FILTER_PATTERN
import static au.org.ala.cas.client.UriFilter.URI_FILTER_PATTERN
import static org.jasig.cas.client.configuration.ConfigurationKeys.*
import static org.jasig.cas.client.configuration.ConfigurationStrategyName.WEB_XML

class AlaAuthBootStrap {

    private static final Logger logger = Logger.getLogger(AlaAuthBootStrap)

    def grailsApplication

    def init = { ServletContext servletContext ->
//        mergeConfig(grailsApplication)
        def config = grailsApplication.config

        // Work around Tomcat bug #53758 which affects the Ubuntu 12.04 tomcat7 package
        def defaultInvertIsMatchAfter = false
        try {
            def serverInfo = "org.apache.catalina.util.ServerInfo" as Class
            String serverNumber = serverInfo.getServerNumber()
            log.error("ALA Auth Plugin running on Catalina $serverNumber")
            def parts = serverNumber.split('\\.')
            if (parts.length > 2) {
                def major = parts[0] as Integer
                def minor = parts[1] as Integer
                def patch = parts[2] as Integer
                if (major == 7 && minor == 0 && patch < 30) {
                    defaultInvertIsMatchAfter = true // work around a Tomcat bug that inverts the order of the isMatchAfter parameter
                }
            }
        } catch (GroovyCastException e) {
            // ignore, not running in Tomcat
        } catch (Exception e) {
            log.warn("Exception extracting tomcat version number", e)
        }

        def invertIsMatchAfter = (config.security.cas.isSet('invertIsMatchAfter') ? config.security.casinvertIsMatchAfter : defaultInvertIsMatchAfter).toBoolean()

        servletContext.setInitParameter('configurationStrategy', WEB_XML.name())

        def appServerName = config.security.cas.appServerName
        def service = config.security.cas.service
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
        servletContext.setInitParameter(CAS_SERVER_URL_PREFIX.name, config.security.cas.casServerUrlPrefix)
        servletContext.setInitParameter(CAS_SERVER_LOGIN_URL.name, config.security.cas.loginUrl)

        servletContext.setInitParameter('casServerName', config.security.cas.casServerName)

        servletContext.setInitParameter(URI_FILTER_PATTERN, config.security.cas.uriFilterPattern)
        servletContext.setInitParameter(URI_EXCLUSION_FILTER_PATTERN, config.security.cas.uriExclusionFilterPattern)
        servletContext.setInitParameter(AUTHENTICATE_ONLY_IF_LOGGED_IN_FILTER_PATTERN, config.security.cas.authenticateOnlyIfLoggedInPattern)

        def encodeServiceUrl = config.security.cas.encodeServiceUrl
        if (isBoolesque(encodeServiceUrl)) {
            servletContext.setInitParameter(ENCODE_SERVICE_URL.name, encodeServiceUrl.toString())
        }

        def contextPath = config.security.cas.contextPath
        if (contextPath) {
            log.warn("Setting security.cas.contextPath ($contextPath) is unnecessary, ala-cas-client can now retrieve it from the ServletContext")
            servletContext.setInitParameter('contextPath', contextPath)
        }

        def gateway = config.security.cas.gateway
        if (isBoolesque(gateway)) {
            servletContext.setInitParameter(GATEWAY.name, gateway.toString())
        }

        def gatewayStorageClass = config.security.cas.gatewayStorageClass
        if (gatewayStorageClass) {
            servletContext.setInitParameter(GATEWAY_STORAGE_CLASS.name, gatewayStorageClass)
        }

        def renew = config.security.cas.renew
        if (isBoolesque(renew)) {
            servletContext.setInitParameter(RENEW.name, renew.toString())
        }

        def disableCAS = config.security.cas.bypass.toString()

        servletContext.addFilter('CAS Single Sign Out Filter', SingleSignOutFilter).with {
            asyncSupported = true
            addMappingForUrlPatterns(EnumSet.noneOf(DispatcherType), invertIsMatchAfter, '/*')
        }

        servletContext.addFilter('CAS Authentication Filter', UriFilter).with {
            asyncSupported = true
            setInitParameter( 'filterClass', AuthenticationFilter.name)
            setInitParameter( 'disableCAS', disableCAS)
            addMappingForUrlPatterns(EnumSet.noneOf(DispatcherType), invertIsMatchAfter, '/*')
        }

        servletContext.addFilter('CAS Validation Filter', UriFilter).with {
            asyncSupported = true
            setInitParameter( 'filterClass', Cas30ProxyReceivingTicketValidationFilter.name)
            setInitParameter( 'disableCAS', disableCAS)
            addMappingForUrlPatterns(EnumSet.noneOf(DispatcherType), invertIsMatchAfter, '/*')
        }

        servletContext.addFilter('CAS HttpServletRequestWrapper Filter', UriFilter).with {
            asyncSupported = true
            setInitParameter( 'filterClass', AlaHttpServletRequestWrapperFilter.name)
            setInitParameter( 'disableCAS', disableCAS)
            addMappingForUrlPatterns(EnumSet.noneOf(DispatcherType), invertIsMatchAfter, '/*')
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
