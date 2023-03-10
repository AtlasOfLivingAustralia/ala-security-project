package au.org.ala.web

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

/**
 * Strategy for implementing SSO.  Used by the SSO Interceptor to generalise authentication method
 */
interface SSOStrategy {

    /**
     * Authenticate a request with the SSO provider
     *
     * @param request The current request
     * @param response The current response
     * @param gateway Whether the request is allowed to callback without authenticating
     * @return true if the request will be authenticated, false if no authentication is required.
     */
    boolean authenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway)

    /**
     * Authenticate a request with the SSO provider
     *
     * @param request The current request
     * @param response The current response
     * @param gateway Whether the request is allowed to callback without authenticating
     * @param redirectUri A redirect URI within the current app to redirect to
     * @return true if the request will be authenticated, false if no authentication is required.
     */
    boolean authenticate(HttpServletRequest request, HttpServletResponse response, boolean gateway, String redirectUri)

}