package au.org.ala.ws.security

import org.springframework.web.context.request.RequestContextHolder

import javax.servlet.http.HttpServletRequest

/**
 * Auth service providing convenience methods for accessing common auth properties.
 */
class AuthService {

    def grailsApplication

    def serviceMethod() {}

    def getEmail() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        request.getUserPrincipal()?.getName()
    }

    def getUserId() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        request.getUserPrincipal()?.principal?.attributes?.userid
    }

    def getDisplayName() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        request.getUserPrincipal()?.principal?.attributes?.firstname
    }

    def getFirstName() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        request.getUserPrincipal()?.principal?.attributes?.firstname
    }

    def getLastName() {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        request.getUserPrincipal()?.principal?.attributes?.lastname
    }

    boolean userInRole(role) {
        def request = RequestContextHolder.currentRequestAttributes().getRequest() as HttpServletRequest
        def inRole = request.isUserInRole(role)
        def bypass = grailsApplication.config.security.cas.bypass
        log.debug("userInRole(${role}) - ${inRole} (bypassing CAS - ${bypass})")
        return bypass.toString().toBoolean() || inRole
    }
}
