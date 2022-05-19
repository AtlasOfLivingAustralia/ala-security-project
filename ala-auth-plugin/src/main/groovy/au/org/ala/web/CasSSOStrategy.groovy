package au.org.ala.web

import groovy.util.logging.Slf4j
import org.grails.web.servlet.mvc.GrailsWebRequest
import org.jasig.cas.client.Protocol
import org.jasig.cas.client.authentication.AuthenticationFilter
import org.jasig.cas.client.authentication.AuthenticationRedirectStrategy
import org.jasig.cas.client.authentication.DefaultAuthenticationRedirectStrategy
import org.jasig.cas.client.authentication.GatewayResolver
import org.jasig.cas.client.authentication.UrlPatternMatcherStrategy
import org.jasig.cas.client.util.CommonUtils
import org.jasig.cas.client.validation.Assertion

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Slf4j
class CasSSOStrategy implements SSOStrategy {

    // The CAS service param to use
    String service
    // The app server name to use
    String serverName
    // CAS Login URL
    String casServerLoginUrl
    // ALA Cookie Name
    String authCookieName
    // Whether to encode the service URL
    boolean encodeServiceUrl
    // Whether CAS is enabled
    boolean enabled
    // Whether all CAS is permitted to allow SSO or whether it must re-authenticate users
    boolean renew
    // Matcher for ignoring URLs
    UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategy
    // Filter out unwanted user agents
    UserAgentFilterService userAgentFilterService
    // Storage for gateway requests
    GatewayResolver gatewayStorage

    Protocol protocol = Protocol.CAS3

    AuthenticationRedirectStrategy authenticationRedirectStrategy = new DefaultAuthenticationRedirectStrategy()

    CasSSOStrategy(String service, String serverName, String casServerLoginUrl, String authCookieName,
                   boolean encodeServiceUrl, boolean enabled, boolean renew, UrlPatternMatcherStrategy ignoreUrlPatternMatcherStrategy, UserAgentFilterService userAgentFilterService, GatewayResolver gatewayStorage) {
        this.service = service
        this.serverName = serverName
        this.casServerLoginUrl = casServerLoginUrl
        this.authCookieName = authCookieName
        this.encodeServiceUrl = encodeServiceUrl
        this.enabled = enabled
        this.renew = renew
        this.ignoreUrlPatternMatcherStrategy = ignoreUrlPatternMatcherStrategy
        this.userAgentFilterService = userAgentFilterService
        this.gatewayStorage = gatewayStorage
    }

    @Override
    boolean authenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway) {
        authenticate(request, response, gateway, null)
    }

    @Override
    boolean authenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway, String redirectUri) {
        if (isRequestUrlExcluded(request)) {
            log.debug("Request is ignored.")
            return true
        }

        final session = request.getSession(false)
        final Assertion assertion = session != null ? (Assertion) session.getAttribute(AuthenticationFilter.CONST_CAS_ASSERTION) : null

        if (assertion != null) {
            def gwr = GrailsWebRequest.lookup(request)
            log.debug("{}.{}.{} request already authenticated", gwr?.controllerNamespace, gwr?.controllerName, gwr?.actionName)
            return true
        }

        final String serviceUrl = constructServiceUrl(request, response, redirectUri)
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

    protected final String constructServiceUrl(final HttpServletRequest request, final HttpServletResponse response, final String redirectUri) {
        return CommonUtils.constructServiceUrl(request, response, redirectUri ?: this.service, this.serverName,
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
