package au.org.ala.web

import groovy.util.logging.Slf4j
import org.jasig.cas.client.configuration.ConfigurationStrategyName
import org.jasig.cas.client.session.SingleSignOutHttpSessionListener
import org.springframework.boot.web.servlet.ServletContextInitializer
import org.springframework.stereotype.Component

import javax.servlet.ServletContext
import javax.servlet.ServletException

import static org.jasig.cas.client.configuration.ConfigurationKeys.*

@Component
@Slf4j
class CasContextParamInitializer implements ServletContextInitializer {

    private final CasClientProperties casClientProperties

    CasContextParamInitializer(CasClientProperties casClientProperties) {
        this.casClientProperties = casClientProperties
    }

    @Override
    void onStartup(ServletContext servletContext) throws ServletException {
        log.debug("CAS Servlet Context Initializer")

        servletContext.addListener(SingleSignOutHttpSessionListener)

        servletContext.setInitParameter('configurationStrategy', ConfigurationStrategyName.WEB_XML.name())

        def appServerName = casClientProperties.appServerName
        def service = casClientProperties.service
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
        servletContext.setInitParameter(CAS_SERVER_URL_PREFIX.name, casClientProperties.casServerUrlPrefix)
        servletContext.setInitParameter(CAS_SERVER_LOGIN_URL.name, casClientProperties.loginUrl)
        servletContext.setInitParameter(ROLE_ATTRIBUTE.name, casClientProperties.roleAttribute)
        servletContext.setInitParameter(IGNORE_PATTERN.name, casClientProperties.uriExclusionFilterPattern.join(','))
        servletContext.setInitParameter(IGNORE_URL_PATTERN_TYPE.name, RegexListUrlPatternMatcherStrategy.name)

        def ignoreCase = casClientProperties.ignoreCase
        if (isBoolesque(ignoreCase)) {
            servletContext.setInitParameter(IGNORE_CASE.name, ignoreCase.toString())
        }

        servletContext.setInitParameter('casServerName', casClientProperties.casServerName)

        def encodeServiceUrl = casClientProperties.encodeServiceUrl
        if (isBoolesque(encodeServiceUrl)) {
            servletContext.setInitParameter(ENCODE_SERVICE_URL.name, encodeServiceUrl.toString())
        }

        def contextPath = casClientProperties.contextPath
        if (contextPath) {
            log.warn("Setting security.cas.contextPath is unnecessary, ala-cas-client can now retrieve it from the ServletContext")
            servletContext.setInitParameter('contextPath', contextPath)
        }

        def gatewayStorageClass = casClientProperties.gatewayStorageClass
        if (gatewayStorageClass) {
            servletContext.setInitParameter(GATEWAY_STORAGE_CLASS.name, gatewayStorageClass)
        }

        def renew = casClientProperties.renew
        if (isBoolesque(renew)) {
            servletContext.setInitParameter(RENEW.name, renew.toString())
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
