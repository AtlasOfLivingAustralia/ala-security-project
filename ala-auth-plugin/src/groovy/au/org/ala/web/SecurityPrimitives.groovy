package au.org.ala.web

import au.org.ala.cas.util.AuthenticationCookieUtils
import org.codehaus.groovy.grails.commons.GrailsApplication

/**
 * Created by bea18c on 31/03/2014.
 */
class SecurityPrimitives {

    private final AuthService authService
    private final GrailsApplication grailsApplication

    SecurityPrimitives(AuthService authService, GrailsApplication grailsApplication) {
        this.authService = authService
        this.grailsApplication = grailsApplication
    }

    /**
     * Is the current user logged in?
     */
    boolean isLoggedIn() {
        authService.userDetails() != null
    }

    /**
     * Is the current user logged in?  Bypasses the authService and checks the request details instead.
     *
     * @param request The http request object
     * @return true if logged in
     */
    boolean isLoggedIn(request) {
        AuthenticationCookieUtils.cookieExists(request, AuthenticationCookieUtils.ALA_AUTH_COOKIE) || request.userPrincipal
    }

    /**
     * Is the current user not logged in?
     */
    boolean isNotLoggedIn() {
        return authService.userDetails() == null
    }

    /**
     * Is the current user not logged in?  Bypasses the authService and checks the request details instead.
     *
     * @param request The http request object
     * @return true if logged out
     */
    boolean isNotLoggedIn(request) {
        !isLoggedIn(request)
    }

    /**
     * Does the currently logged in user have any of the given roles?
     *
     * @param roles A list of roles to check
     */
    boolean isAnyGranted(Iterable<String> roles) {
        fixAlaAdminRole(roles).any { role ->
            authService.userInRole(role?.trim())
        }
    }

    /**
     * Does the currently logged in user have all of the given roles?
     *
     * @param roles A list of roles to check
     */
    boolean isAllGranted(Iterable<String> roles) {
        fixAlaAdminRole(roles).every { role ->
            authService.userInRole(role?.trim())
        }
    }

    /**
     * Does the currently logged in user have none of the given roles?
     *
     * @param roles A list of roles to check
     */
    boolean isNotGranted(Iterable<String> roles) {
        !isAnyGranted(roles)
    }

    /**
     * Replace CASRoles.ROLE_ADMIN Role with the security.cas.adminRole property if it's defined.
     * @param roles The list of roles to modify
     * @return The roles with ROLE_ADMIN replaced
     */
    private Iterable<String> fixAlaAdminRole(Iterable<String> roles) {
        def adminRole = grailsApplication.config.security.cas.adminRole
        !adminRole ? roles : roles.collect { role ->
            CASRoles.ROLE_ADMIN == role ? adminRole : role
        }
    }
}
