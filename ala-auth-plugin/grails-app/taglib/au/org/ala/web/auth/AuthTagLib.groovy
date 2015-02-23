package au.org.ala.web.auth

import au.org.ala.cas.util.AuthenticationCookieUtils
import grails.util.Holders

class AuthTagLib {

    def authService
    def securityPrimitives // gets injected in AlaWebThemeGrailsPlugin 'doWithSpring' section

    def grailServerURL = Holders.config.grails.serverURL ?: "http://bie.ala.org.au"
    // the next two can also be overridden by tag attributes
    def casLoginUrl = Holders.config.security.cas.loginUrl ?: "https://auth.ala.org.au/cas/login"
    def casLogoutUrl = Holders.config.security.cas.logoutUrl ?: "https://auth.ala.org.au/cas/logout"

    static namespace = "auth"
    //static encodeAsForTags = [tagName: 'raw']

    /**
     * Is the user logged in?
     */
    def ifLoggedIn = { attrs, body ->
        if (securityPrimitives.isLoggedIn(request)) out << body()
    }

    /**
     * Is the user not logged in?
     */
    def ifNotLoggedIn = { attrs, body ->
        if (securityPrimitives.isNotLoggedIn(request)) out << body()
    }

    /**
     * Does the currently logged in user have any of the given roles?
     *
     * @attr roles REQUIRED A comma separated list of roles to check
     */
    def ifAnyGranted = { attrs, body ->
        if (securityPrimitives.isAnyGranted(rolesStringToList(attrs))) out << body()
    }

    /**
     * Does the currently logged in user have all of the given roles?
     *
     * @attr roles REQUIRED A comma separated list of roles to check
     */
    def ifAllGranted = { attrs, body ->
        if (securityPrimitives.isAllGranted(rolesStringToList(attrs))) out << body()
    }

    /**
     * Does the currently logged in user have none of the given roles?
     *
     * @attr roles REQUIRED A comma separated list of roles to check
     */
    def ifNotGranted = { attrs, body ->
        if (securityPrimitives.isNotGranted(rolesStringToList(attrs))) out << body()
    }

    /**
     * Generate the login/logout link (taken from ala-web-theme plugin)
     *
     * @attr cssClass - CSS class to add to a tag
     *
     * plus
     * @attr logoutUrl the local url that should invalidate the session and redirect to the auth
     *  logout url - defaults to {CH.config.grails.serverURL}/session/logout
     * @attr loginReturnToUrl where to go after logging in - defaults to current page
     * @attr logoutReturnToUrl where to go after logging out - defaults to current page
     * @attr loginReturnUrl where to go after login - defaults to current page
     * @attr casLoginUrl - defaults to {CH.config.security.cas.loginUrl}
     * @attr casLogoutUrl - defaults to {CH.config.security.cas.logoutUrl}
     * @attr ignoreCookie - if true the helper cookie will not be used to determine login - defaults to false
     */
    def loginLogout = { attrs ->
        out << buildLoginoutLink(attrs)
    }

    /**
     * Builds the login or logout link based on current login status.
     * @param attrs any specified params to override defaults
     * @return
     */
    String buildLoginoutLink(attrs) {
        def requestUri = removeContext(grailServerURL) + request.forwardURI
        def logoutUrl = attrs.logoutUrl ?: grailServerURL + "/session/logout"
        def logoutReturnToUrl = attrs.logoutReturnToUrl ?: requestUri
        def casLogoutUrl = attrs.casLogoutUrl ?: casLogoutUrl

        // TODO should this be attrs.logoutReturnToUrl?
        if (!attrs.loginReturnToUrl && request.queryString) {
            logoutReturnToUrl += "?" + URLEncoder.encode(request.queryString, "UTF-8")
        }

        if ((attrs.ignoreCookie != "true" &&
                AuthenticationCookieUtils.cookieExists(request, AuthenticationCookieUtils.ALA_AUTH_COOKIE)) ||
                request.userPrincipal) {
            return "<a href='${logoutUrl}" +
                    "?casUrl=${casLogoutUrl}" +
                    "&appUrl=${logoutReturnToUrl}' " +
                    "class='${attrs.cssClass}'>Logout</a>"
        } else {
            // currently logged out
            return "<a href='${buildLoginLink(attrs)}' class='${attrs.cssClass}'><span>Log in</span></a>"
        }
    }

    /**
     * Build the login link
     * @param attrs any specified params to override defaults
     * @return The login url
     */
    String buildLoginLink(attrs) {
        def casLoginUrl = attrs.casLoginUrl ?: casLoginUrl
        def loginReturnToUrl = attrs.loginReturnToUrl ?: (removeContext(grailServerURL) + request.forwardURI + (request.queryString ? "?" + URLEncoder.encode(request.queryString, "UTF-8") : ""))
        String loginUrl = "${casLoginUrl}?service=${loginReturnToUrl}"
        return loginUrl
    }

    /**
     * Remove the context path and params from the url.
     * @param urlString
     * @return
     */
    private String removeContext(urlString) {
        def url = urlString.toURL()
        def protocol = url.protocol != -1 ? url.protocol + "://" : ""
        def port = url.port != -1 ? ":" + url.port : ""
        return protocol + url.host + port
    }

    private def rolesStringToList(attrs) {
        def roles = attrs.roles ?: ""
        def split = roles.split(",")
        def list = split.toList()
        return list
    }
}
