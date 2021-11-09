package au.org.ala.ws.security

import au.ala.org.ws.security.RequireApiKey
import au.ala.org.ws.security.SkipApiKeyCheck
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.security.authentication.AbstractAuthenticationToken
import javax.servlet.http.HttpServletResponse
import java.security.Principal

/**
 * An authentication interceptor that checks a user is logged in and has the required roles as specified
 * using the @RequireApiKey
 */
@CompileStatic
@Slf4j
class AlaAuthInterceptor {

    AlaAuthInterceptor() {
        matchAll()
    }

    /**
     * Executed before a matched action.
     *
     * @return Whether the action should continue and execute
     */
    boolean before() {

        def controller = grailsApplication.getArtefactByLogicalPropertyName("Controller", controllerName)
        Class controllerClass = controller?.clazz
        def method = controllerClass?.getMethod(actionName ?: "index", [] as Class[])

        def classLevelAnnotation = controllerClass?.isAnnotationPresent(RequireApiKey)
        def methodLevelSkipAnnotation = method?.isAnnotationPresent(SkipApiKeyCheck)
        def methodLevelAnnotation = method?.isAnnotationPresent(RequireApiKey)

        if ((classLevelAnnotation && !methodLevelSkipAnnotation) || methodLevelAnnotation) {

            def userPrincipal = request.getUserPrincipal()

            if (userPrincipal) {

                List roles = getUserRoles(userPrincipal)

                RequireApiKey classLevelRequireApiKey = controllerClass.getAnnotation(RequireApiKey.class)
                RequireApiKey methodLevelRequireApiKey = method.getAnnotation(RequireApiKey.class)

                if (classLevelRequireApiKey && classLevelRequireApiKey.requiredRoles()) {
                    // resolve role property
                    String[] requiredRoles = classLevelRequireApiKey.requiredRoles().split(",")
                    // check roles
                    requiredRoles.each { requiredRole ->
                        //TODO check grailsApplication.config.'requiredRole'
                        if (!roles.contains(requiredRole)) {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
                            return false
                        }
                    }
                }

                if (methodLevelRequireApiKey && methodLevelRequireApiKey.requiredRoles()) {
                    // resolve role property
                    String[] requiredRoles = methodLevelRequireApiKey.requiredRoles().split(",")
                    // check roles
                    //TODO check grailsApplication.config.'requiredRole'
                    requiredRoles.each { requiredRole ->
                        if (!roles.contains(requiredRole)) {
                            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
                            return false
                        }
                    }
                }

                true

            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
                false
            }
        } else {
            true
        }
    }

    private List getUserRoles(Principal userPrincipal) {
        List roles = []
        if (userPrincipal instanceof AbstractAuthenticationToken) {
            if (userPrincipal && userPrincipal?.authorities) {
                roles << ((AbstractAuthenticationToken) userPrincipal).authorities
            }
        }
        roles
    }

    /**
     * Executed after the action executes but prior to view rendering
     *
     * @return True if view rendering should continue, false otherwise
     */
    boolean after() { true }

    /**
     * Executed after view rendering completes
     */
    void afterView() {}

//    List getUserRoles(principal) {
//        List roles = []
//        if (principal && principal?.authorities){
//            roles << authorities
//        }
//
//        if (principal && principal?.principal?.attributes?.role){
//           if (principal.principal.attributes.role){
//               roles << roles
//           }
//        }
//        roles
//    }
}