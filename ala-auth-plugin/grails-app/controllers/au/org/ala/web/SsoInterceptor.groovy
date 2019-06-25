package au.org.ala.web

import au.org.ala.web.config.AuthPluginConfig
import grails.core.GrailsApplication
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.jasig.cas.client.Protocol
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.authentication.AuthenticationRedirectStrategy
import org.jasig.cas.client.authentication.DefaultAuthenticationRedirectStrategy
import org.jasig.cas.client.authentication.GatewayResolver
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy
import org.jasig.cas.client.util.CommonUtils
import org.jasig.cas.client.validation.Assertion
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value

import javax.annotation.PostConstruct
import javax.servlet.http.Cookie
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@CompileStatic
@Slf4j
class SsoInterceptor {

    int order = HIGHEST_PRECEDENCE

    @Value('${security.cas.service:}')
    String service

    @Value('${security.cas.appServerName:}')
    String serverName

    @Value('${security.cas.loginUrl:}')
    String casServerLoginUrl

    @Value('${security.cas.authCookieName:ALA-Auth}')
    String authCookieName

    @Value('${security.cas.encodeServiceUrl:true}')
    boolean encodeServiceUrl

    @Value('${security.cas.enabled:true}')
    boolean enabled

    @Value('${security.cas.renew:false}')
    boolean renew

    @Autowired
    UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategy

    @Autowired
    UserAgentFilterService userAgentFilterService

    @Autowired
    GatewayResolver gatewayStorage

    Protocol protocol = Protocol.CAS3

    AuthenticationRedirectStrategy authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy()

    @Autowired
    GrailsApplication grailsApplication

    SsoInterceptor() {
//        matchAll().except(uri: '/error')
    }

    @PostConstruct
    void init() {
        if (enabled) {
            AnnotationMatcher.matchAnnotation(this, grailsApplication, SSO)
        }
    }

    boolean before() {
        if (!enabled) return true
        if (request.getAttribute(AuthPluginConfig.AUTH_FILTER_KEY)) return true

        final result = AnnotationMatcher.getAnnotation(grailsApplication, controllerNamespace, controllerName, actionName, SSO, NoSSO)
        final controllerAnnotation = result.controllerAnnotation
        final actionAnnotation = result.actionAnnotation
        final actionNoSso = result.overrideAnnotation

        if (actionNoSso) return true

        if (!controllerAnnotation && !actionAnnotation) return true

        def effectiveAnnotation = result.effectiveAnnotation()

        if (effectiveAnnotation.cookie() && !cookieExists(request)) {
            log.debug("{}.{}.{} requested the presence of a {} cookie but none was found", controllerNamespace, controllerName, actionName, authCookieName)
            return true
        }

        def userAgent = request.getHeader('User-Agent')
        if ((effectiveAnnotation.gateway()) && userAgentFilterService.isFiltered(userAgent)) {
            log.debug("{}.{}.{} skipping SSO because it is gateway and the user agent is filtered", controllerNamespace, controllerName, actionName)
            return true
        }

        return doCasAuthenticate(request, response, effectiveAnnotation.gateway(), renew)
    }

    boolean after() { true }

    void afterView() {
        // no-op
    }

    boolean doCasAuthenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway, boolean renew) {

        if (isRequestUrlExcluded(request)) {
            log.debug("Request is ignored.")
            return true
        }

        final session = request.getSession(false)
        final Assertion assertion = session != null ? (Assertion) session.getAttribute(AuthenticationFilter.CONST_CAS_ASSERTION) : null

        if (assertion != null) {
            log.debug("{}.{}.{} request already authenticated", controllerNamespace, controllerName, actionName)
            return true
        }

        final String serviceUrl = constructServiceUrl(request, response)
        final String ticket = retrieveTicketFromRequest(request)
        final boolean wasGatewayed = gateway && this.gatewayStorage.hasGatewayedAlready(request, serviceUrl)

        if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
            return true
        }

        final String modifiedServiceUrl

        log.debug("no ticket and no assertion found")
        if (gateway) {
            log.debug("setting gateway attribute in session")
            modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl)
        } else {
            modifiedServiceUrl = serviceUrl
        }

        log.debug("Constructed service url: {}", modifiedServiceUrl)

        final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl,
                getProtocol().getServiceParameterName(), modifiedServiceUrl, renew, gateway)

        log.debug("redirecting to \"{}\"", urlToRedirectTo)
        this.authenticationRedirectStrategy.redirect(request, response, urlToRedirectTo)

        return false
    }

    protected final String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response) {
        return CommonUtils.constructServiceUrl(request, response, this.service, this.serverName,
                this.protocol.getServiceParameterName(),
                this.protocol.getArtifactParameterName(), this.encodeServiceUrl)
    }

    /**
     * Template method to allow you to change how you retrieve the ticket.
     *
     * @param request the HTTP ServletRequest.  CANNOT be NULL.
     * @return the ticket if its found, null otherwise.
     */
    protected String retrieveTicketFromRequest(final HttpServletRequest request) {
        return CommonUtils.safeGetParameter(request, this.protocol.getArtifactParameterName())
    }

    protected boolean cookieExists(final HttpServletRequest request) {
        return request.cookies.any { Cookie cookie -> cookie.name == this.authCookieName && cookie.value}
    }

    private boolean isRequestUrlExcluded(final HttpServletRequest request) {
        if (this.ignoreUrlPatternMatcherStrategy == null) {
            return false
        }

        final StringBuffer urlBuffer = request.getRequestURL()
        if (request.getQueryString() != null) {
            urlBuffer.append("?").append(request.getQueryString())
        }
        final String requestUri = urlBuffer.toString()
        return this.ignoreUrlPatternMatcherStrategy.matches(requestUri)
    }
}
