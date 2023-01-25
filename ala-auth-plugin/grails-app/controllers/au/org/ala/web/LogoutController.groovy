package au.org.ala.web

import org.pac4j.core.util.Pac4jConstants
import org.springframework.beans.factory.annotation.Autowired

class LogoutController {

    @Autowired
    CoreAuthProperties coreAuthProperties

    /**
     * Do logouts through this app so we can invalidate the session.
     *
     * Note this controller is only used for CAS logouts, OIDC logouts use the Pac4j LogoutFilter.
     *
     * @param casUrl the url for logging out of cas
     * @param appUrl the url to redirect back to after the logout
     */
    def logout() {
        session.invalidate()
        def appUrl = URLEncoder.encode(validateLogoutRedirectUrl(params.url ?: params.appUrl), "UTF-8")
        def casUrl = grailsApplication.config.getProperty('security.cas.logoutUrl')
        redirect(url:"${casUrl}?url=${appUrl}")
    }

    /**
     * Check that the appUrl for logout is a part of the current app and convert it to an absolute URI for logout if
     * required
     *
     * @param appUrl the appUrl parameter value
     * @return The appUrl if it's a valid URL for this app or this app's / URI
     */
    private String validateLogoutRedirectUrl(String appUrl) {
        def uri
        String retVal
        def logoutPattern = coreAuthProperties.logoutUrlPattern ?: Pac4jConstants.DEFAULT_LOGOUT_URL_PATTERN_VALUE
        try {
            uri = appUrl?.toURI()
        } catch (URISyntaxException e) {
            uri = null
        }
        // For an absolute URI, make sure it's allowed by the pattern *OR* that it starts with
        // our current base URI and the relative part matches the pattern
        // For a relative URI, make sure it's allowed
        if (uri == null || uri.isAbsolute()) {
            def baseUrl = g.createLink(absolute: true, uri: '/').toString()
            if (appUrl.matches(logoutPattern)) {
                retVal = appUrl
            } else if (appUrl?.startsWith(baseUrl) && uri.toString().substring(baseUrl.length()).matches(logoutPattern)) {
                retVal = appUrl
            } else {
                retVal = coreAuthProperties.defaultLogoutRedirectUri
            }
        } else {

            if (appUrl.matches(logoutPattern)) {
                retVal = request.requestURL.toURI().resolve(appUrl).toString()
            } else {
                retVal = coreAuthProperties.defaultLogoutRedirectUri
            }
        }
        return retVal
    }

    /**
     * Clear the headers and footers cache
     *
     */
    def clearCache() {
        render hf.clearCache()
    }
}
