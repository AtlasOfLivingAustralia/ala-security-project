package au.org.ala.web

class LogoutController {


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
        def appUrl = URLEncoder.encode(validateAppUrl(params.appUrl), "UTF-8")
        def casUrl = grailsApplication.config.security.cas.logoutUrl
        redirect(url:"${casUrl}?url=${appUrl}")
    }

    /**
     * Check that the appUrl for logout is a part of the current app
     *
     * @param appUrl the appUrl parameter value
     * @return The appUrl if it's a valid URL for this app or this app's / URI
     */
    private String validateAppUrl(String appUrl) {
        def baseUrl = g.createLink(absolute: true, uri: '/')
        def retVal
        if (appUrl?.startsWith(baseUrl)) {
            retVal = appUrl
        } else {
            retVal = baseUrl
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
