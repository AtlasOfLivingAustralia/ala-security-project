package au.org.ala.ws.security

import grails.converters.JSON
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
                if (classLevelRequireApiKey && classLevelRequireApiKey.value()) {
                    // resolve role property
                    if (!hasSufficientRoles(classLevelRequireApiKey)) {
                        sendUnAuthorized(request)
                        return false
                    }
                }

                // check method level roles
                if (methodLevelRequireApiKey && methodLevelRequireApiKey.value()) {
                    if (!hasSufficientRoles(methodLevelRequireApiKey)) {
                        sendUnAuthorized(request)
                        return false
                    }
                }

                // we have checked the roles
                true
            } else {
                sendForbidden(request)
                false
            }
        } else {
            // no annotations, let the request through
            true
        }
    }

    private void sendUnAuthorized(request) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write((["error":"Unauthorized", "statusCode": HttpServletResponse.SC_UNAUTHORIZED] as JSON).toString());

    }

    private void sendForbidden(request) {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write((["error":"Forbidden", "statusCode": HttpServletResponse.SC_FORBIDDEN] as JSON).toString());

    }

    private boolean hasSufficientRoles(RequireAuth requireApiKeyAnnotation) {
        String[] requiredRoles = requireApiKeyAnnotation.value()
        if (requiredRoles) {
            // check user has at least one of the required roles
            requiredRoles.find { requiredRole ->
                request.isUserInRole(requiredRole)
            }
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