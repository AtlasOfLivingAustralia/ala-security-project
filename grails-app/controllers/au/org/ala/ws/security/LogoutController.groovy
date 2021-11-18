package au.org.ala.ws.security

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler

class LogoutController {



    def index() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        authentication.setAuthenticated(false);
        new SecurityContextLogoutHandler().logout(request,response,authentication);

        SecurityContextHolder.clearContext();
        request.logout()
        session.invalidate()

        redirect(url: "http://dev.ala.org.au:8080")
    }

    /**
     * Do logouts through this app so we can invalidate the session.
     *
     * @param casUrl the url for logging out of cas
     * @param appUrl the url to redirect back to after the logout
     */
    def logout() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        authentication.setAuthenticated(false);
        new SecurityContextLogoutHandler().logout(request,response,authentication);

        SecurityContextHolder.clearContext();
        request.logout()
        session.invalidate()

        def appUrl = URLEncoder.encode(params.appUrl ?: g.createLink(uri: '/'), "UTF-8")
        def casUrl = grailsApplication.config.security.logoutUrl ?: grailsApplication.config.security.cas.logoutUrl
        redirect(url:"${casUrl}?url=${appUrl}")
    }
}