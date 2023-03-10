package au.org.ala.web

import grails.core.GrailsApplication

import javax.servlet.http.HttpServletRequest

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
        authService.userId != null
    }

    /**
     * Is the current user logged in?  Bypasses the authService and checks the request details instead.
     *
     * @param request The http request object
     * @return true if logged in
     */
    boolean isLoggedIn(HttpServletRequest request) {
        request.userPrincipal != null
    }

    /**
     * Is the current user not logged in?
     */
    boolean isNotLoggedIn() {
        return authService.userId == null
    }

    /**
     * Is the current user not logged in?  Bypasses the authService and checks the request details instead.
     *
     * @param request The http request object
     * @return true if logged out
     */
    boolean isNotLoggedIn(HttpServletRequest request) {
        !isLoggedIn(request)
    }

    boolean bypassCas() {
        def bypass = grailsApplication.config.getProperty('security.cas.bypass')
        return bypass?.toString()?.toBoolean() ?: false
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
     * Does the currently logged in user have any of the given roles?
     *
     * @param roles A list of roles to check
     */
    boolean isAnyGranted(HttpServletRequest request, Iterable<String> roles) {
        bypassCas() || fixAlaAdminRole(roles).any { role ->
            request.isUserInRole(role)
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
     * Does the currently logged in user have all of the given roles?
     *
     * @param roles A list of roles to check
     */
    boolean isAllGranted(HttpServletRequest request, Iterable<String> roles) {
        bypassCas() || fixAlaAdminRole(roles).every { role ->
            request.isUserInRole(role)
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
     * Does the currently logged in user have none of the given roles?
     *
     * @param roles A list of roles to check
     */
    boolean isNotGranted(HttpServletRequest request, Iterable<String> roles) {
        bypassCas() || !isAnyGranted(request, roles)
    }

    /**
     * Replace CASRoles.ROLE_ADMIN Role with the security.cas.adminRole property if it's defined.
     * @param roles The list of roles to modify
     * @return The roles with ROLE_ADMIN replaced
     */
    private Iterable<String> fixAlaAdminRole(Iterable<String> roles) {
        def adminRole = grailsApplication.config.getProperty('security.cas.adminRole') ?: ''
        adminRole && roles?.contains(CASRoles.ROLE_ADMIN) ? roles + adminRole : roles
    }
}
