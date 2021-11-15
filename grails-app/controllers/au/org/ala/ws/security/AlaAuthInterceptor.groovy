package au.org.ala.ws.security

import au.ala.org.ws.security.RequireAuth
import au.ala.org.ws.security.SkipAuthCheck
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import javax.servlet.http.HttpServletResponse

/**
 * An authentication interceptor that checks a user is logged in and has the required roles as specified
 * using the @RequireAuth annotations
 *
 * see @RequireAuth
 * see @SkipAuthCheck
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

        def classLevelAnnotation = controllerClass?.isAnnotationPresent(RequireAuth)
        def methodLevelSkipAnnotation = method?.isAnnotationPresent(SkipAuthCheck)
        def methodLevelAnnotation = method?.isAnnotationPresent(RequireAuth)

        if ((classLevelAnnotation && !methodLevelSkipAnnotation) || methodLevelAnnotation) {

            def userPrincipal = request.getUserPrincipal()

            if (userPrincipal) {

                RequireAuth classLevelRequireApiKey = controllerClass.getAnnotation(RequireAuth.class)
                RequireAuth methodLevelRequireApiKey = method.getAnnotation(RequireAuth.class)

                // check class level roles
                if (classLevelRequireApiKey && classLevelRequireApiKey.requiredRoles()) {
                    // resolve role property
                    if (!hasSufficientRoles(classLevelRequireApiKey)) {
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
                        return false
                    }
                }

                // check method level roles
                if (methodLevelRequireApiKey && methodLevelRequireApiKey.requiredRoles()) {
                    if (!hasSufficientRoles(methodLevelRequireApiKey)) {
                        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
                        return false
                    }
                }

                // we have check the roles
                true
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden")
                false
            }
        } else {
            true
        }
    }


    private boolean hasSufficientRoles(RequireAuth requireApiKeyAnnotation) {
        String[] requiredRoles = requireApiKeyAnnotation.requiredRoles()
        if (requiredRoles) {
            // check user has at least one of the required roles
            requiredRoles.each { requiredRole ->
                if (request.isUserInRole(requiredRole)) {
                    return true
                }
            }
            false
        } else {
            true
        }
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
}